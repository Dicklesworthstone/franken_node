#!/usr/bin/env python3
"""Inventory-backed placeholder regression scanner for bd-2fqyv.1.2.

This scanner treats ``docs/governance/placeholder_surface_inventory.md`` as the
authoritative policy boundary for placeholder/demo/simulated surfaces.

The exit semantics are intentionally narrow:
- PASS when all suspicious markers are either explicitly allowlisted test
  fixtures or already-documented inventory debt at the expected source anchors.
- FAIL when a marker escapes its temporary allowlist, appears in an
  undocumented path, or when the inventory/truth anchors drift out of sync.

The scanner does not claim the placeholder-remediation program is complete.
It is a regression guard for documented boundaries, not a declaration that all
inventory debt has been removed.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

PARENT_BEAD = "bd-2fqyv"
SUPPORT_BEAD = "bd-2fqyv.1.2"
INVENTORY_DOC_REL = "docs/governance/placeholder_surface_inventory.md"
ARTIFACT_DIR_REL = "artifacts/program/bd-2fqyv.1.3"
EVIDENCE_PATH_REL = f"{ARTIFACT_DIR_REL}/verification_evidence.json"
SUMMARY_PATH_REL = f"{ARTIFACT_DIR_REL}/verification_summary.md"

STATIC_PASS = "PLACEHOLDER_SCANNER_PASS"
INVENTORY_DRIFT = "PLACEHOLDER_SCANNER_INVENTORY_DRIFT"
MISSING_ANCHOR = "PLACEHOLDER_SCANNER_MISSING_ANCHOR"
ALLOWLIST_ESCAPE = "PLACEHOLDER_SCANNER_ALLOWLIST_ESCAPE"
UNEXPECTED_OCCURRENCE = "PLACEHOLDER_SCANNER_UNDOCUMENTED_OCCURRENCE"

SCAN_ROOTS = ("crates", "sdk", "scripts", "tests", "docs")
SCAN_EXTENSIONS = {".md", ".py", ".rs", ".sh", ".toml"}


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    surface: str
    classification: str
    markers: tuple[str, ...]
    search_paths: tuple[str, ...]
    allowed_paths: tuple[str, ...] = ()
    documented_paths: tuple[str, ...] = ()
    allowed_line_substrings: tuple[str, ...] = ()
    required_anchor_markers: tuple[str, ...] = ()
    anchor_paths: tuple[str, ...] = ()
    inventory_id: str | None = None
    allowed_simulation_label: str | None = None
    remediation_bead: str = PARENT_BEAD
    related_checkers: tuple[str, ...] = ()


@dataclass(frozen=True)
class RepoFile:
    path: str
    text: str
    test_lines: frozenset[int]


@dataclass(frozen=True)
class Occurrence:
    path: str
    line: int
    marker: str
    context: str
    line_text: str


RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="fixture_registry_boundary",
        surface="fixture trust-card registry remains test-only",
        classification="allowlisted_simulation",
        markers=("fixture_registry(",),
        search_paths=("crates/**/*.rs", "tests/**/*.rs"),
        allowed_paths=(
            "crates/franken-node/src/main.rs",
            "crates/franken-node/src/supply_chain/trust_card.rs",
            "crates/franken-node/src/api/trust_card_routes.rs",
            "crates/franken-node/tests/trust_cli_e2e.rs",
        ),
        allowed_line_substrings=("fn fixture_registry(",),
        allowed_simulation_label="fixture_registry(...)",
        remediation_bead="bd-2fqyv.2",
        related_checkers=("scripts/check_trust_card.py",),
    ),
    RuleSpec(
        rule_id="decision_receipt_demo_key_boundary",
        surface="decision receipt demo signing key remains fixture-only",
        classification="allowlisted_simulation",
        markers=("demo_signing_key(",),
        search_paths=(
            "crates/franken-node/src/security/decision_receipt.rs",
            "crates/franken-node/tests/verify_release_cli_e2e.rs",
            "tests/integration/decision_receipt_export.rs",
            "scripts/check_artifact_signing.py",
        ),
        allowed_paths=(
            "crates/franken-node/src/security/decision_receipt.rs",
            "crates/franken-node/tests/verify_release_cli_e2e.rs",
            "tests/integration/decision_receipt_export.rs",
            "scripts/check_artifact_signing.py",
        ),
        allowed_line_substrings=(
            "fn demo_signing_key(",
            "demo_signing_key().verifying_key()",
            '"pub fn demo_signing_key("',
        ),
        allowed_simulation_label="decision_receipt::demo_signing_key(...)",
        remediation_bead="bd-2fqyv.3",
        related_checkers=("scripts/check_signed_receipt.py",),
    ),
    RuleSpec(
        rule_id="no_legacy_demo_receipt_export",
        surface="legacy demo receipt export path removed from live CLI",
        classification="disallowed_live_shortcut",
        markers=("maybe_export_demo_receipts(",),
        search_paths=("crates/franken-node/src/main.rs",),
        required_anchor_markers=(
            "fn maybe_export_signed_receipts(",
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            "decision_receipt_signing_key_path",
        ),
        anchor_paths=(
            "crates/franken-node/src/main.rs",
            "crates/franken-node/src/config.rs",
        ),
        inventory_id="PSI-002",
        remediation_bead="bd-2fqyv.3",
        related_checkers=("scripts/check_signed_receipt.py",),
    ),
    RuleSpec(
        rule_id="incident_fixture_event_boundary",
        surface="incident fixture-event helper remains test-only",
        classification="allowlisted_simulation",
        markers=("fixture_incident_events(",),
        search_paths=("crates/**/*.rs",),
        allowed_paths=(
            "crates/franken-node/src/main.rs",
            "crates/franken-node/src/tools/replay_bundle.rs",
        ),
        allowed_line_substrings=("fn fixture_incident_events(",),
        inventory_id="PSI-003",
        allowed_simulation_label="fixture_incident_events(...)",
        remediation_bead="bd-2fqyv.4",
        related_checkers=("scripts/check_replay_bundle.py",),
    ),
    RuleSpec(
        rule_id="service_skeleton_quarantine",
        surface="control-plane catalog boundary remains explicitly non-live",
        classification="deferred_skeleton",
        markers=(
            "TransportBoundaryKind::InProcessCatalog",
            "UnavailablePendingTransport",
            "synthetic_bearer_admin_route(",
        ),
        search_paths=("crates/**/*.rs", "docs/**/*.md"),
        allowed_paths=("crates/franken-node/src/api/service.rs",),
        documented_paths=(
            "crates/franken-node/src/api/service.rs",
            "docs/architecture/blueprint.md",
            "docs/architecture/tri_kernel_ownership_contract.md",
        ),
        allowed_line_substrings=("fn synthetic_bearer_admin_route(",),
        required_anchor_markers=(
            "TransportBoundaryKind::InProcessCatalog",
            "UnavailablePendingTransport",
            "in-process catalog/dispatch layer",
        ),
        anchor_paths=(
            "crates/franken-node/src/api/service.rs",
            "docs/architecture/blueprint.md",
            "docs/architecture/tri_kernel_ownership_contract.md",
        ),
        inventory_id="PSI-004",
        allowed_simulation_label="synthetic_bearer_admin_route()",
        remediation_bead="bd-2fqyv.5",
    ),
    RuleSpec(
        rule_id="migration_truth_anchor",
        surface="migration surface stays explicitly audit/rewrite/validate only",
        classification="truthful_partial_surface",
        markers=(),
        search_paths=("crates/franken-node/src/main.rs", "crates/franken-node/src/migration/mod.rs"),
        documented_paths=("crates/franken-node/src/main.rs", "crates/franken-node/src/migration/mod.rs"),
        required_anchor_markers=(
            "MigrateCommand::Rewrite(args)",
            "MigrateCommand::Validate(args)",
            "MigrationRewriteAction::ManualScriptReview",
            "engines.node",
        ),
        anchor_paths=("crates/franken-node/src/main.rs", "crates/franken-node/src/migration/mod.rs"),
        inventory_id="PSI-005",
        remediation_bead="bd-2fqyv.6",
    ),
    RuleSpec(
        rule_id="fuzz_gate_simulation_confinement",
        surface="fuzz gate simulation remains confined to its modeling surface",
        classification="allowlisted_simulation",
        markers=("simulated crash", "coverage_pct: 0.0"),
        search_paths=("crates/franken-node/src/connector/fuzz_corpus.rs",),
        documented_paths=("crates/franken-node/src/connector/fuzz_corpus.rs",),
        required_anchor_markers=("simulated crash", "coverage_pct: 0.0"),
        anchor_paths=("crates/franken-node/src/connector/fuzz_corpus.rs",),
        inventory_id="PSI-006",
        remediation_bead="bd-2fqyv.7",
        related_checkers=("scripts/check_fuzz_corpus.py",),
    ),
    RuleSpec(
        rule_id="fuzz_gate_callsite_boundary",
        surface="fuzz gate callsites remain confined to fixture and verification paths",
        classification="allowlisted_simulation",
        markers=(".run_gate(",),
        search_paths=("crates/**/*.rs", "tests/**/*.rs"),
        allowed_paths=(
            "crates/franken-node/src/connector/fuzz_corpus.rs",
            "tests/integration/fuzz_corpus_gates.rs",
        ),
        allowed_line_substrings=("pub fn run_gate(",),
        inventory_id="PSI-006",
        remediation_bead="bd-2fqyv.7",
        related_checkers=("scripts/check_fuzz_corpus.py",),
    ),
    RuleSpec(
        rule_id="obligation_tracker_drop_rollback_guardrail",
        surface="obligation guard drop path remains a real rollback with cleanup diagnostics",
        classification="disallowed_live_shortcut",
        markers=(
            "In a real implementation this would call tracker.rollback().",
            "[OBL-DROP] ObligationGuard dropped without resolution",
            "logs instead of rolling back",
        ),
        search_paths=("crates/**/*.rs", "docs/**/*.md"),
        required_anchor_markers=(
            "impl Drop for ObligationGuard",
            "tracker: Arc<Mutex<TrackerState>>",
            "obligation rolled back by guard drop",
            "OBL_DROP_SKIPPED",
        ),
        anchor_paths=("crates/franken-node/src/connector/obligation_tracker.rs",),
        remediation_bead="bd-2fqyv.8",
    ),
    RuleSpec(
        rule_id="ecosystem_health_placeholder_metrics",
        surface="ecosystem health export placeholder metrics stay explicitly documented",
        classification="truthful_partial_surface",
        markers=("compromise_reduction_factor: 1.0", "certification_distribution: BTreeMap::new()"),
        search_paths=("crates/**/*.rs",),
        documented_paths=("crates/franken-node/src/supply_chain/ecosystem_telemetry.rs",),
        required_anchor_markers=(
            "compromise_reduction_factor: 1.0",
            "certification_distribution: BTreeMap::new()",
        ),
        anchor_paths=("crates/franken-node/src/supply_chain/ecosystem_telemetry.rs",),
        inventory_id="PSI-008",
        remediation_bead="bd-2fqyv.9",
    ),
    RuleSpec(
        rule_id="dgis_placeholder_barrier_context",
        surface="DGIS no-barrier receipts remain explicit not-applicable outcomes",
        classification="truthful_partial_surface",
        markers=(
            "Build a synthetic barrier for the receipt",
            "fn make_pass_receipt(",
            "passthrough-",
        ),
        search_paths=("crates/**/*.rs", "docs/**/*.md"),
        required_anchor_markers=(
            "BARRIER_CHECK_NOT_APPLICABLE",
            "make_not_applicable_receipt(",
            "BarrierAction::NotApplicable",
            "not-applicable:",
            "check_passes_when_no_barriers_exist",
        ),
        anchor_paths=("crates/franken-node/src/security/dgis/barrier_primitives.rs",),
        inventory_id="PSI-009",
        remediation_bead="bd-2fqyv.11",
    ),
    RuleSpec(
        rule_id="reproduction_script_simulated_verification",
        surface="external reproduction script remains explicitly simulated until replaced",
        classification="disallowed_live_shortcut",
        markers=("verification simulated (full execution requires test harness)",),
        search_paths=("scripts/reproduce.py", "docs/**/*.md"),
        documented_paths=("scripts/reproduce.py",),
        required_anchor_markers=("def verify_claim(", "def run_reproduction("),
        anchor_paths=("scripts/reproduce.py",),
        inventory_id="PSI-010",
        remediation_bead="bd-2fqyv.10",
    ),
)


def parse_markdown_table_section(text: str, heading: str) -> list[dict[str, str]]:
    """Parse a simple GitHub-flavored Markdown table under a section heading."""
    lines = text.splitlines()
    in_section = False
    header: list[str] | None = None
    rows: list[dict[str, str]] = []

    for line in lines:
        stripped = line.strip()
        if stripped == heading:
            in_section = True
            header = None
            continue
        if in_section and stripped.startswith("## "):
            break
        if not in_section or not stripped.startswith("|"):
            continue

        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        if header and len(cells) == len(header):
            rows.append(dict(zip(header, cells, strict=True)))
    return rows


def load_inventory_tables(root: Path = ROOT) -> dict[str, list[dict[str, str]]]:
    inventory_text = (root / INVENTORY_DOC_REL).read_text(encoding="utf-8")
    return {
        "inventory": parse_markdown_table_section(inventory_text, "## Inventory"),
        "allowed_simulations": parse_markdown_table_section(inventory_text, "## Allowed Simulations"),
    }


def _iter_repo_files(root: Path = ROOT) -> dict[str, RepoFile]:
    files: dict[str, RepoFile] = {}
    for scan_root in SCAN_ROOTS:
        base = root / scan_root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in SCAN_EXTENSIONS:
                continue
            rel_path = path.relative_to(root).as_posix()
            text = path.read_text(encoding="utf-8")
            files[rel_path] = RepoFile(
                path=rel_path,
                text=text,
                test_lines=frozenset(_rust_test_lines(text) if _is_rust_source(rel_path) else set()),
            )
    return files


def _is_rust_source(rel_path: str) -> bool:
    return rel_path.endswith(".rs")


def _is_test_file(rel_path: str) -> bool:
    return (
        rel_path.startswith("tests/")
        or rel_path.startswith("crates/franken-node/tests/")
        or rel_path.endswith("_test.py")
        or rel_path.endswith("_tests.py")
    )


def _rust_test_lines(text: str) -> set[int]:
    lines = text.splitlines()
    test_lines: set[int] = set()
    pending_cfg_test = False
    idx = 0
    while idx < len(lines):
        line_no = idx + 1
        stripped = lines[idx].strip()
        if pending_cfg_test:
            test_lines.add(line_no)
            if "{" in lines[idx]:
                depth = lines[idx].count("{") - lines[idx].count("}")
                idx += 1
                while idx < len(lines):
                    test_lines.add(idx + 1)
                    depth += lines[idx].count("{") - lines[idx].count("}")
                    if depth <= 0:
                        break
                    idx += 1
                pending_cfg_test = False
            elif stripped.startswith("#["):
                pass
            else:
                pending_cfg_test = False
            idx += 1
            continue
        if "#[cfg(test)]" in stripped:
            pending_cfg_test = True
            test_lines.add(line_no)
        idx += 1
    return test_lines


def _matches_any(rel_path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(rel_path, pattern) for pattern in patterns)


def _context_for_line(repo_file: RepoFile, line_no: int) -> str:
    if _is_test_file(repo_file.path):
        return "test"
    if line_no in repo_file.test_lines:
        return "test"
    return "production"


def _find_occurrences(rule: RuleSpec, repo_files: dict[str, RepoFile]) -> list[Occurrence]:
    occurrences: list[Occurrence] = []
    for repo_file in repo_files.values():
        if repo_file.path == INVENTORY_DOC_REL:
            continue
        if not _matches_any(repo_file.path, rule.search_paths):
            continue
        for line_no, raw_line in enumerate(repo_file.text.splitlines(), start=1):
            for marker in rule.markers:
                if marker in raw_line:
                    occurrences.append(
                        Occurrence(
                            path=repo_file.path,
                            line=line_no,
                            marker=marker,
                            context=_context_for_line(repo_file, line_no),
                            line_text=raw_line.strip(),
                        )
                    )
    occurrences.sort(key=lambda item: (item.path, item.line, item.marker))
    return occurrences


def _load_text(path: str, root: Path = ROOT) -> str:
    target = root / path
    return target.read_text(encoding="utf-8") if target.exists() else ""


def _inventory_alignment_failures(
    rule: RuleSpec,
    tables: dict[str, list[dict[str, str]]],
) -> list[str]:
    failures: list[str] = []
    if rule.inventory_id is not None:
        inventory_rows = tables["inventory"]
        match = next((row for row in inventory_rows if row.get("ID") == f"`{rule.inventory_id}`"), None)
        if match is None:
            failures.append(f"inventory row missing: {rule.inventory_id}")
        elif match.get("Classification") != f"`{rule.classification}`":
            failures.append(
                f"inventory classification drift for {rule.inventory_id}: "
                f"expected {rule.classification}, found {match.get('Classification')}"
            )
    if rule.allowed_simulation_label is not None:
        allowed_rows = tables["allowed_simulations"]
        if not any(rule.allowed_simulation_label in row.get("Surface", "") for row in allowed_rows):
            failures.append(f"allowed simulation row missing: {rule.allowed_simulation_label}")
    return failures


def _anchor_failures(rule: RuleSpec, root: Path = ROOT) -> list[str]:
    if not rule.required_anchor_markers:
        return []
    combined = "\n".join(_load_text(path, root) for path in rule.anchor_paths)
    return [marker for marker in rule.required_anchor_markers if marker not in combined]


def evaluate_rule(
    rule: RuleSpec,
    root: Path = ROOT,
    repo_files: dict[str, RepoFile] | None = None,
    tables: dict[str, list[dict[str, str]]] | None = None,
) -> dict[str, Any]:
    repo_files = repo_files or _iter_repo_files(root)
    tables = tables or load_inventory_tables(root)

    documented: list[dict[str, Any]] = []
    allowlisted: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    escapes: list[dict[str, Any]] = []

    for occurrence in _find_occurrences(rule, repo_files):
        entry = {
            "path": occurrence.path,
            "line": occurrence.line,
            "marker": occurrence.marker,
            "context": occurrence.context,
            "line_text": occurrence.line_text,
        }
        if _matches_any(occurrence.path, rule.documented_paths):
            documented.append(entry)
            continue
        if _matches_any(occurrence.path, rule.allowed_paths):
            if occurrence.context == "test" or any(
                marker in occurrence.line_text for marker in rule.allowed_line_substrings
            ):
                allowlisted.append(entry)
            else:
                escapes.append(entry)
            continue
        if _matches_any(occurrence.path, rule.documented_paths):
            documented.append(entry)
            continue
        unexpected.append(entry)

    inventory_failures = _inventory_alignment_failures(rule, tables)
    anchor_failures = _anchor_failures(rule, root)

    if inventory_failures:
        reason_code = INVENTORY_DRIFT
    elif anchor_failures:
        reason_code = MISSING_ANCHOR
    elif escapes:
        reason_code = ALLOWLIST_ESCAPE
    elif unexpected:
        reason_code = UNEXPECTED_OCCURRENCE
    else:
        reason_code = STATIC_PASS

    return {
        "rule_id": rule.rule_id,
        "surface": rule.surface,
        "classification": rule.classification,
        "inventory_id": rule.inventory_id,
        "allowed_simulation_label": rule.allowed_simulation_label,
        "remediation_bead": rule.remediation_bead,
        "related_checkers": list(rule.related_checkers),
        "documented_occurrences": documented,
        "allowlisted_occurrences": allowlisted,
        "unexpected_occurrences": unexpected,
        "allowlist_escapes": escapes,
        "inventory_alignment_failures": inventory_failures,
        "missing_anchor_markers": anchor_failures,
        "documented_occurrence_count": len(documented),
        "allowlisted_occurrence_count": len(allowlisted),
        "unexpected_occurrence_count": len(unexpected),
        "allowlist_escape_count": len(escapes),
        "pass": not any((inventory_failures, anchor_failures, escapes, unexpected)),
        "reason_code": reason_code,
    }


def run_all(root: Path = ROOT) -> dict[str, Any]:
    repo_files = _iter_repo_files(root)
    tables = load_inventory_tables(root)
    rules = [evaluate_rule(rule, root=root, repo_files=repo_files, tables=tables) for rule in RULES]
    failed_rules = [rule for rule in rules if not rule["pass"]]
    documented_occurrences = sum(rule["documented_occurrence_count"] for rule in rules)
    allowlisted_occurrences = sum(rule["allowlisted_occurrence_count"] for rule in rules)
    unexpected_occurrences = sum(rule["unexpected_occurrence_count"] for rule in rules)
    allowlist_escapes = sum(rule["allowlist_escape_count"] for rule in rules)
    missing_anchor_total = sum(len(rule["missing_anchor_markers"]) for rule in rules)
    inventory_drift_total = sum(len(rule["inventory_alignment_failures"]) for rule in rules)

    return {
        "schema_version": "placeholder-surface-scanner-v1.0",
        "bead_id": SUPPORT_BEAD,
        "parent_bead_id": PARENT_BEAD,
        "inventory_doc": INVENTORY_DOC_REL,
        "verification_method": "python3 scripts/check_placeholder_surface_inventory.py --json",
        "artifacts": {
            "verification_evidence": EVIDENCE_PATH_REL,
            "verification_summary": SUMMARY_PATH_REL,
        },
        "verdict": "PASS" if not failed_rules else "FAIL",
        "overall_pass": not failed_rules,
        "summary": {
            "rule_count": len(RULES),
            "inventory_entry_count": len(tables["inventory"]),
            "allowed_simulation_count": len(tables["allowed_simulations"]),
            "documented_occurrences": documented_occurrences,
            "allowlisted_occurrences": allowlisted_occurrences,
            "unexpected_occurrences": unexpected_occurrences,
            "allowlist_escapes": allowlist_escapes,
            "missing_anchor_markers": missing_anchor_total,
            "inventory_drift_failures": inventory_drift_total,
        },
        "temporary_allowlist_strategy": {
            "pass_condition": (
                "Documented open debt may remain at its declared anchors, but any "
                "undocumented occurrence, allowlist escape, missing truth anchor, "
                "or inventory drift fails the scan."
            ),
            "modes": [
                {
                    "mode": "explicit_test_fixture",
                    "description": "Marker is allowed only in listed fixture/test paths or on the explicitly allowlisted helper line.",
                },
                {
                    "mode": "documented_open_debt",
                    "description": "Marker is temporarily tolerated only at the inventory-declared live path until the owning remediation bead closes.",
                },
                {
                    "mode": "truth_anchor",
                    "description": "Truthful partial or deferred surfaces must retain the honesty markers that keep their narrow scope explicit.",
                },
            ],
            "steady_state": (
                "The final ratchet should shrink documented_open_debt to zero and "
                "leave only explicit test fixtures with narrowly scoped allowlists."
            ),
        },
        "rules": rules,
        "failed_rules": [rule["rule_id"] for rule in failed_rules],
    }


def write_artifacts(payload: dict[str, Any], root: Path = ROOT) -> None:
    artifact_dir = root / ARTIFACT_DIR_REL
    artifact_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = artifact_dir / "verification_evidence.json"
    evidence_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = payload["summary"]
    lines = [
        "# Placeholder Surface Inventory Gate",
        "",
        f"- Parent bead: `{payload['parent_bead_id']}`",
        f"- Support bead: `{payload['bead_id']}`",
        f"- Verdict: `{payload['verdict']}`",
        f"- Inventory doc: `{payload['inventory_doc']}`",
        f"- Rule count: `{summary['rule_count']}`",
        f"- Documented open-debt occurrences: `{summary['documented_occurrences']}`",
        f"- Allowlisted fixture occurrences: `{summary['allowlisted_occurrences']}`",
        f"- Unexpected occurrences: `{summary['unexpected_occurrences']}`",
        f"- Allowlist escapes: `{summary['allowlist_escapes']}`",
        "",
        "## Documented Open Debt",
    ]

    documented_rules = [
        rule for rule in payload["rules"] if rule["documented_occurrence_count"] > 0
    ]
    if documented_rules:
        for rule in documented_rules:
            label = rule["inventory_id"] or rule["rule_id"]
            lines.append(
                f"- `{label}` {rule['surface']}: "
                f"{rule['documented_occurrence_count']} documented occurrence(s); "
                f"owner `{rule['remediation_bead']}`."
            )
    else:
        lines.append("- None.")

    lines.extend(["", "## Explicit Allowlists"])
    allowlisted_rules = [
        rule for rule in payload["rules"] if rule["allowlisted_occurrence_count"] > 0
    ]
    if allowlisted_rules:
        for rule in allowlisted_rules:
            rationale = rule["allowed_simulation_label"] or rule["classification"]
            lines.append(
                f"- `{rule['rule_id']}` {rule['surface']}: "
                f"{rule['allowlisted_occurrence_count']} allowlisted occurrence(s); "
                f"rationale `{rationale}`."
            )
    else:
        lines.append("- None.")

    lines.extend(["", "## Failures"])
    if payload["failed_rules"]:
        for rule in payload["rules"]:
            if rule["rule_id"] in payload["failed_rules"]:
                lines.append(
                    f"- `{rule['rule_id']}` failed via `{rule['reason_code']}`."
                )
    else:
        lines.append("- None.")

    summary_path = artifact_dir / "verification_summary.md"
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> bool:
    rule = RuleSpec(
        rule_id="toy",
        surface="toy fixture helper",
        classification="allowlisted_simulation",
        markers=("fixture_registry(",),
        search_paths=("crates/**/*.rs",),
        allowed_paths=("crates/franken-node/src/main.rs",),
        allowed_line_substrings=("fn fixture_registry(",),
        allowed_simulation_label="fixture_registry(...)",
    )

    inventory_doc = """# Placeholder Surface Inventory

## Inventory

| ID | Classification | Surface | Entry points / files | Reachability | Current behavior | Remediation owner |
|---|---|---|---|---|---|---|

## Allowed Simulations

| Surface | Why it is allowed |
|---|---|
| `fixture_registry(...)` inside tests | explicit fixture |
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        inventory_path = root / INVENTORY_DOC_REL
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(inventory_doc, encoding="utf-8")

        target = root / "crates/franken-node/src/main.rs"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "#[cfg(test)]\nmod tests {\n    fn sample() { let _ = fixture_registry(1); }\n}\n",
            encoding="utf-8",
        )
        allowed = evaluate_rule(rule, root=root)
        if not allowed["pass"]:
            return False

        target.write_text("fn live() { let _ = fixture_registry(1); }\n", encoding="utf-8")
        escaped = evaluate_rule(rule, root=root)
        return escaped["reason_code"] == ALLOWLIST_ESCAPE


def _print_human(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    print(
        f"{SUPPORT_BEAD} placeholder scanner: {payload['verdict']} "
        f"({summary['rule_count']} rules, "
        f"{summary['documented_occurrences']} documented, "
        f"{summary['allowlisted_occurrences']} allowlisted)"
    )
    for rule in payload["rules"]:
        status = "PASS" if rule["pass"] else "FAIL"
        print(f"- [{status}] {rule['rule_id']}: {rule['reason_code']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run internal consistency checks")
    parser.add_argument(
        "--write-artifacts",
        action="store_true",
        help="write verification_evidence.json and verification_summary.md",
    )
    args = parser.parse_args(argv)

    logger = configure_test_logging("check_placeholder_surface_inventory", json_mode=args.json)

    if args.self_test:
        ok = self_test()
        logger.info("self-test complete", extra={"passed": ok})
        if args.json:
            print(json.dumps({"self_test": ok}, indent=2, sort_keys=True))
        else:
            print("self_test PASSED" if ok else "self_test FAILED")
        return 0 if ok else 1

    payload = run_all()
    if args.write_artifacts:
        write_artifacts(payload)
    logger.info(
        "placeholder surface inventory scan complete",
        extra={
            "verdict": payload["verdict"],
            "failed_rules": len(payload["failed_rules"]),
            "documented_occurrences": payload["summary"]["documented_occurrences"],
        },
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(payload)
    return 0 if payload["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
