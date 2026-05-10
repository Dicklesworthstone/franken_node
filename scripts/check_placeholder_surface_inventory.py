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
import re
import sys
import tempfile
import tomllib
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
DOCS_TRUTH_DRIFT = "DOCS_TRUTH_DRIFT"

DOCS_TRUTH_BEAD = "bd-15zqy"
FEATURE_DOCS = ("AGENTS.md", "docs/ARCHITECTURE_OVERVIEW.md")
TOOLCHAIN_DOCS = ("AGENTS.md", "docs/ARCHITECTURE_OVERVIEW.md")
REPRODUCTION_STATUS_DOCS = (
    "docs/governance/placeholder_surface_inventory.md",
    "docs/reproduction_playbook.md",
)
REPRODUCTION_ANCHORS = (
    "def verify_claim(",
    "subprocess.run(",
    "procedure executed successfully and met threshold",
    '"run_mode": "executed"',
)
STALE_REPRODUCTION_MARKERS = (
    "verification simulated (full execution requires test harness)",
    "script currently emits `pass: true`",
    "simulates claim verification",
)

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
            "crates/franken-node/tests/fleet_cli_e2e.rs",
            "crates/franken-node/tests/golden/trust_card_golden_tests.rs",
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
        markers=("maybe_export_demo_receipts(", "maybe_export_signed_receipts("),
        search_paths=("crates/franken-node/src/main.rs",),
        required_anchor_markers=(
            "fn export_signed_receipts(",
            "struct ReceiptExportContext",
            "fn prepare_receipt_export_context(",
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
        allowed_paths=(
            "crates/franken-node/src/api/service.rs",
            "crates/franken-node/src/api/mod.rs",
            "crates/franken-node/tests/fastapi_rust_control_plane_integration.rs",
        ),
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
        surface="deterministic fuzz fixture adapter remains confined to its modeling surface",
        classification="allowlisted_simulation",
        markers=("synthetic_test_fixture", "coverage_pct: 0.0"),
        search_paths=("crates/franken-node/src/connector/fuzz_corpus.rs",),
        documented_paths=("crates/franken-node/src/connector/fuzz_corpus.rs",),
        required_anchor_markers=(
            "DeterministicFuzzTestAdapter",
            "run_fixture_gate(",
            "synthetic_test_fixture",
            "coverage_pct: 0.0",
        ),
        anchor_paths=("crates/franken-node/src/connector/fuzz_corpus.rs",),
        inventory_id="PSI-006",
        remediation_bead="bd-2fqyv.7",
        related_checkers=("scripts/check_fuzz_corpus.py",),
    ),
    RuleSpec(
        rule_id="fuzz_gate_callsite_boundary",
        surface="deterministic fuzz fixture callsites remain confined to fixture and verification paths",
        classification="allowlisted_simulation",
        markers=(".run_fixture_gate(",),
        search_paths=("crates/**/*.rs", "tests/**/*.rs"),
        allowed_paths=(
            "crates/franken-node/src/connector/fuzz_corpus.rs",
            "tests/integration/fuzz_corpus_gates.rs",
        ),
        allowed_line_substrings=("pub fn run_fixture_gate(",),
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
        surface="ecosystem health export keeps explicit availability/provenance markers for derived metrics",
        classification="truthful_partial_surface",
        markers=(),
        search_paths=("crates/**/*.rs",),
        documented_paths=("crates/franken-node/src/supply_chain/ecosystem_telemetry.rs",),
        required_anchor_markers=(
            "pub compromise_reduction_factor: Option<f64>",
            "pub compromise_reduction_metadata: DerivedMetricMetadata",
            "pub certification_distribution_metadata: DerivedMetricMetadata",
            "DerivedMetricAvailability::MissingUpstream",
            "DerivedMetricAvailability::StaleUpstream",
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
        surface="external reproduction script executes mapped verification procedures",
        classification="truthful_partial_surface",
        markers=("verification simulated (full execution requires test harness)",),
        search_paths=("scripts/reproduce.py", "docs/**/*.md"),
        required_anchor_markers=REPRODUCTION_ANCHORS,
        anchor_paths=("scripts/reproduce.py",),
        inventory_id="PSI-010",
        remediation_bead="bd-2fqyv.10",
    ),
    RuleSpec(
        rule_id="time_travel_fixture_identity_replay_boundary",
        surface="time-travel identity replay remains fixture-only baseline evidence",
        classification="allowlisted_simulation",
        markers=("fixture_identity_replay(", "replay_fixture_identity("),
        search_paths=("crates/**/*.rs", "tests/**/*.rs"),
        allowed_paths=(
            "crates/franken-node/src/replay/time_travel_engine.rs",
            "crates/franken-node/src/replay/replay_conformance_tests.rs",
            "crates/franken-node/src/replay/mod.rs",
            "tests/lab/time_travel_replay_equivalence.rs",
            "tests/conformance/replay_clock_drift_detection.rs",
        ),
        allowed_line_substrings=(
            "pub fn fixture_identity_replay(",
            "pub fn replay_fixture_identity(",
        ),
        required_anchor_markers=(
            "Fixture-only replay function",
            "must not be cited as production replay evidence",
            "Production/operator flows",
            "self.replay(trace_id, fixture_identity_replay)",
        ),
        anchor_paths=("crates/franken-node/src/replay/time_travel_engine.rs",),
        inventory_id="PSI-011",
        allowed_simulation_label="fixture_identity_replay(...)",
        remediation_bead="bd-oetof",
        related_checkers=("scripts/check_time_travel_replay.py",),
    ),
    RuleSpec(
        rule_id="activation_fixture_executor_boundary",
        surface="connector activation fixture executor remains baseline-only evidence",
        classification="allowlisted_simulation",
        markers=("FixtureActivationExecutor", "ACTIVATION_EXECUTOR_REQUIRED"),
        search_paths=("crates/**/*.rs", "tests/**/*.rs"),
        allowed_paths=(
            "crates/franken-node/src/connector/activation_pipeline.rs",
            "tests/integration/activation_pipeline_determinism.rs",
        ),
        allowed_line_substrings=(
            "`FixtureActivationExecutor`, which must not be cited as production",
            "Fixture-only activation executor",
            "pub struct FixtureActivationExecutor;",
            "impl StageExecutor for FixtureActivationExecutor",
            "const ACTIVATION_EXECUTOR_REQUIRED: &str =",
            '"ACTIVATION_EXECUTOR_REQUIRED: no real activation executor configured"',
            "Err(ACTIVATION_EXECUTOR_REQUIRED.to_string())",
        ),
        required_anchor_markers=(
            "Fail-closed production default",
            "Fixture-only activation executor",
            "must not be cited as production activation evidence",
            "Err(ACTIVATION_EXECUTOR_REQUIRED.to_string())",
        ),
        anchor_paths=("crates/franken-node/src/connector/activation_pipeline.rs",),
        inventory_id="PSI-012",
        allowed_simulation_label="FixtureActivationExecutor",
        remediation_bead="bd-t1ko8",
        related_checkers=("scripts/check_activation_pipeline.py",),
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
        else:
            expected_classification = f"`{rule.classification}`"
            found_classification = match.get("Classification", "")
            if expected_classification not in found_classification:
                failures.append(
                    f"inventory classification drift for {rule.inventory_id}: "
                    f"expected {rule.classification}, found {found_classification}"
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


def _docs_truth_entry(
    *,
    check_id: str,
    document_path: str,
    passed: bool,
    expected_value: str,
    observed_value: str,
    remediation_hint: str,
    severity: str = "error",
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "document_path": document_path,
        "expected_value": expected_value,
        "observed_value": observed_value,
        "severity": severity,
        "remediation_hint": remediation_hint,
        "trace_id": f"{DOCS_TRUTH_BEAD}:{check_id}",
        "pass": passed,
        "reason_code": STATIC_PASS if passed else DOCS_TRUTH_DRIFT,
    }


def _load_cargo_features(root: Path = ROOT) -> tuple[set[str], set[str]]:
    cargo_path = root / "crates/franken-node/Cargo.toml"
    data = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
    features = data.get("features", {})
    feature_names = set(features) - {"default"}
    default_features = set(features.get("default", []))
    return feature_names, default_features


def _markdown_section(text: str, heading: str) -> str:
    lines = text.splitlines()
    start: int | None = None
    level = 0
    for idx, line in enumerate(lines):
        if line.strip() == heading:
            start = idx + 1
            level = len(line) - len(line.lstrip("#"))
            break
    if start is None:
        return ""
    end = len(lines)
    for idx in range(start, len(lines)):
        stripped = lines[idx].lstrip()
        if stripped.startswith("#"):
            current_level = len(stripped) - len(stripped.lstrip("#"))
            if current_level <= level:
                end = idx
                break
    return "\n".join(lines[start:end])


def _feature_section_for_doc(rel_path: str, text: str) -> str:
    heading = "### Feature Flags" if rel_path == "AGENTS.md" else "## Feature Flags"
    return _markdown_section(text, heading)


def _line_feature_name(line: str) -> str | None:
    stripped = line.strip()
    if stripped.startswith("|"):
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or cells[0].lower() == "feature" or set(cells[0]) <= {"-", ":"}:
            return None
        match = re.search(r"`([a-z][a-z0-9-]+)`", cells[0])
        return match.group(1) if match else None
    match = re.search(r"^-\s+\*\*`([a-z][a-z0-9-]+)`\*\*", stripped)
    return match.group(1) if match else None


def _documented_features(section: str, known_features: set[str]) -> set[str]:
    documented: set[str] = set()
    for line in section.splitlines():
        feature = _line_feature_name(line)
        if feature is not None and (feature in known_features or "-" in feature):
            documented.add(feature)
    return documented


def _documented_default_features(section: str, known_features: set[str]) -> set[str]:
    default_features: set[str] = set()
    for line in section.splitlines():
        lowered = line.lower()
        if "default: enabled" not in lowered:
            continue
        feature = _line_feature_name(line)
        if feature in known_features:
            default_features.add(feature)
    return default_features


def _format_set(values: set[str]) -> str:
    return ", ".join(sorted(values)) if values else "none"


def evaluate_docs_truth(root: Path = ROOT) -> list[dict[str, Any]]:
    feature_names, default_features = _load_cargo_features(root)
    checks: list[dict[str, Any]] = []

    for rel_path in FEATURE_DOCS:
        text = _load_text(rel_path, root)
        section = _feature_section_for_doc(rel_path, text)
        documented = _documented_features(section, feature_names)
        documented_defaults = _documented_default_features(section, feature_names)
        missing = feature_names - documented
        extra = documented - feature_names
        missing_defaults = default_features - documented_defaults
        extra_defaults = documented_defaults - default_features
        passed = not any((missing, extra, missing_defaults, extra_defaults)) and bool(section)
        observed_parts = [
            f"missing={_format_set(missing)}",
            f"extra={_format_set(extra)}",
            f"missing_defaults={_format_set(missing_defaults)}",
            f"extra_defaults={_format_set(extra_defaults)}",
        ]
        if not section:
            observed_parts.append("feature_section=missing")
        checks.append(
            _docs_truth_entry(
                check_id=f"feature_flags:{rel_path}",
                document_path=rel_path,
                passed=passed,
                expected_value=(
                    f"features={_format_set(feature_names)}; "
                    f"default_features={_format_set(default_features)}"
                ),
                observed_value="; ".join(observed_parts),
                remediation_hint=(
                    "Update the Feature Flags section to match "
                    "crates/franken-node/Cargo.toml, including default-enabled markers."
                ),
            )
        )

    toolchain_files = sorted(
        path.relative_to(root).as_posix()
        for path in root.glob("rust-toolchain*")
        if path.is_file()
    )
    stale_toolchain_pattern = re.compile(
        r"Rust\s+2024\s+Edition\s*\([^)]*nightly[^)]*\)|nightly toolchain",
        re.IGNORECASE,
    )
    for rel_path in TOOLCHAIN_DOCS:
        text = _load_text(rel_path, root)
        stale_matches = [
            match.group(0)
            for match in stale_toolchain_pattern.finditer(text)
        ]
        passed = not stale_matches and (bool(toolchain_files) or "Rust 2024" in text)
        checks.append(
            _docs_truth_entry(
                check_id=f"toolchain:{rel_path}",
                document_path=rel_path,
                passed=passed,
                expected_value=(
                    "Rust 2024 documented without a nightly-toolchain claim; "
                    f"rust_toolchain_files={_format_set(set(toolchain_files))}"
                ),
                observed_value=(
                    f"stale_claims={'; '.join(stale_matches) if stale_matches else 'none'}; "
                    f"mentions_rust_2024={'yes' if 'Rust 2024' in text else 'no'}"
                ),
                remediation_hint=(
                    "State Rust 2024 compatibility and the live rust-toolchain file status; "
                    "do not claim this checkout pins nightly unless a rust-toolchain file exists."
                ),
            )
        )

    reproduce_text = _load_text("scripts/reproduce.py", root)
    missing_reproduction_anchors = [
        marker for marker in REPRODUCTION_ANCHORS if marker not in reproduce_text
    ]
    stale_reproduction_hits: list[str] = []
    for rel_path in REPRODUCTION_STATUS_DOCS + ("scripts/reproduce.py",):
        text = _load_text(rel_path, root)
        for marker in STALE_REPRODUCTION_MARKERS:
            if marker in text:
                stale_reproduction_hits.append(f"{rel_path}: {marker}")
    checks.append(
        _docs_truth_entry(
            check_id="reproduction:procedure_execution_status",
            document_path="scripts/reproduce.py",
            passed=not missing_reproduction_anchors and not stale_reproduction_hits,
            expected_value=(
                "scripts/reproduce.py executes mapped procedure_ref/harness_kind/"
                "measurement_key checks and docs do not claim simulated verification"
            ),
            observed_value=(
                f"missing_anchors={_format_set(set(missing_reproduction_anchors))}; "
                f"stale_markers={'; '.join(stale_reproduction_hits) if stale_reproduction_hits else 'none'}"
            ),
            remediation_hint=(
                "Keep dry-run labeled as planned, keep executed runs tied to subprocess "
                "procedure execution, and update governance docs when the reproduction contract changes."
            ),
        )
    )
    return checks


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
    docs_truth_checks = evaluate_docs_truth(root)
    failed_rules = [rule for rule in rules if not rule["pass"]]
    failed_docs_truth_checks = [check for check in docs_truth_checks if not check["pass"]]
    documented_occurrences = sum(rule["documented_occurrence_count"] for rule in rules)
    allowlisted_occurrences = sum(rule["allowlisted_occurrence_count"] for rule in rules)
    unexpected_occurrences = sum(rule["unexpected_occurrence_count"] for rule in rules)
    allowlist_escapes = sum(rule["allowlist_escape_count"] for rule in rules)
    missing_anchor_total = sum(len(rule["missing_anchor_markers"]) for rule in rules)
    inventory_drift_total = sum(len(rule["inventory_alignment_failures"]) for rule in rules)

    return {
        "schema_version": "placeholder-surface-scanner-v1.1",
        "bead_id": SUPPORT_BEAD,
        "parent_bead_id": PARENT_BEAD,
        "inventory_doc": INVENTORY_DOC_REL,
        "verification_method": "python3 scripts/check_placeholder_surface_inventory.py --json",
        "artifacts": {
            "verification_evidence": EVIDENCE_PATH_REL,
            "verification_summary": SUMMARY_PATH_REL,
        },
        "verdict": "PASS" if not failed_rules and not failed_docs_truth_checks else "FAIL",
        "overall_pass": not failed_rules and not failed_docs_truth_checks,
        "summary": {
            "rule_count": len(RULES),
            "docs_truth_check_count": len(docs_truth_checks),
            "inventory_entry_count": len(tables["inventory"]),
            "allowed_simulation_count": len(tables["allowed_simulations"]),
            "documented_occurrences": documented_occurrences,
            "allowlisted_occurrences": allowlisted_occurrences,
            "unexpected_occurrences": unexpected_occurrences,
            "allowlist_escapes": allowlist_escapes,
            "missing_anchor_markers": missing_anchor_total,
            "inventory_drift_failures": inventory_drift_total,
            "docs_truth_failures": len(failed_docs_truth_checks),
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
        "docs_truth_checks": docs_truth_checks,
        "failed_rules": [rule["rule_id"] for rule in failed_rules],
        "failed_docs_truth_checks": [
            check["check_id"] for check in failed_docs_truth_checks
        ],
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
        f"- Docs truth checks: `{summary['docs_truth_check_count']}`",
        f"- Documented open-debt occurrences: `{summary['documented_occurrences']}`",
        f"- Allowlisted fixture occurrences: `{summary['allowlisted_occurrences']}`",
        f"- Unexpected occurrences: `{summary['unexpected_occurrences']}`",
        f"- Allowlist escapes: `{summary['allowlist_escapes']}`",
        f"- Docs truth failures: `{summary['docs_truth_failures']}`",
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
    if payload["failed_docs_truth_checks"]:
        for check in payload["docs_truth_checks"]:
            if check["check_id"] in payload["failed_docs_truth_checks"]:
                lines.append(
                    f"- `{check['check_id']}` failed for `{check['document_path']}`: "
                    f"{check['observed_value']}"
                )
    if not payload["failed_rules"] and not payload["failed_docs_truth_checks"]:
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
            "failed_docs_truth_checks": len(payload["failed_docs_truth_checks"]),
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
