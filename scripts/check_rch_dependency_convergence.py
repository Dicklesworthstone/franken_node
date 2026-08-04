#!/usr/bin/env python3
"""Preflight cross-root Cargo dependency convergence before RCH validation."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - this repo expects Python 3.11+
    tomllib = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "franken-node/rch-dependency-convergence/v1"
DEFAULT_MANIFEST_GLOBS = ("Cargo.toml", "crates/*/Cargo.toml", "sdk/*/Cargo.toml")
DEFAULT_FAIL_EXIT_CODE = 21


@dataclass(frozen=True)
class RootSpec:
    name: str
    path: Path


@dataclass(frozen=True)
class LockedPackage:
    root_name: str
    lockfile_path: Path
    package: str
    version: str


@dataclass(frozen=True)
class Requirement:
    root_name: str
    manifest_path: Path
    owner: str
    package: str
    dependency_key: str
    requirement: str
    section: str


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        raise RuntimeError("tomllib is required; run with Python 3.11 or newer")
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"TOML root must be an object: {path}")
    return payload


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def parse_root_spec(value: str) -> RootSpec:
    if "=" in value:
        name, raw_path = value.split("=", 1)
        name = name.strip()
    else:
        raw_path = value
        name = Path(value).name
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    else:
        path = path.resolve()
    if not name:
        name = path.name or "root"
    return RootSpec(name=name, path=path)


def _manifest_paths(root: RootSpec, globs: tuple[str, ...]) -> list[Path]:
    paths: set[Path] = set()
    for pattern in globs:
        for path in root.path.glob(pattern):
            if path.is_file():
                paths.add(path.resolve())
    return sorted(paths, key=lambda item: item.as_posix())


def parse_lockfile(root: RootSpec) -> list[LockedPackage]:
    lockfile = root.path / "Cargo.lock"
    if not lockfile.exists():
        return []
    payload = _load_toml(lockfile)
    packages = payload.get("package", [])
    if not isinstance(packages, list):
        return []
    locked: list[LockedPackage] = []
    seen: set[tuple[str, str, str]] = set()
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        key = (root.name, name, version)
        if key in seen:
            continue
        seen.add(key)
        locked.append(
            LockedPackage(
                root_name=root.name,
                lockfile_path=lockfile.resolve(),
                package=name,
                version=version,
            )
        )
    return sorted(locked, key=lambda item: (item.package, item.version, item.root_name))


def _iter_dependency_tables(manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    tables: list[tuple[str, dict[str, Any]]] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(section)
        if isinstance(value, dict):
            tables.append((section, value))

    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target_name, target_value in targets.items():
            if not isinstance(target_value, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target_value.get(section)
                if isinstance(value, dict):
                    tables.append((f"target.{target_name}.{section}", value))
    return tables


def _package_owner(manifest_path: Path, payload: dict[str, Any]) -> str:
    package = payload.get("package")
    if isinstance(package, dict) and isinstance(package.get("name"), str):
        return str(package["name"])
    return manifest_path.parent.name


def _dependency_requirement(name: str, spec: Any) -> tuple[str, str] | None:
    if isinstance(spec, str):
        return name, spec.strip()
    if not isinstance(spec, dict):
        return None
    package = spec.get("package", name)
    if not isinstance(package, str):
        return None
    version = spec.get("version")
    if not isinstance(version, str) or not version.strip():
        return None
    workspace_value = spec.get("workspace")
    if isinstance(workspace_value, bool) and workspace_value:
        return None
    return package, version.strip()


def parse_manifest_requirements(root: RootSpec, globs: tuple[str, ...]) -> list[Requirement]:
    requirements: list[Requirement] = []
    for manifest_path in _manifest_paths(root, globs):
        payload = _load_toml(manifest_path)
        owner = _package_owner(manifest_path, payload)
        for section, table in _iter_dependency_tables(payload):
            for dependency_key, spec in sorted(table.items()):
                parsed = _dependency_requirement(str(dependency_key), spec)
                if parsed is None:
                    continue
                package, requirement = parsed
                if requirement in {"*", ""}:
                    continue
                requirements.append(
                    Requirement(
                        root_name=root.name,
                        manifest_path=manifest_path,
                        owner=owner,
                        package=package,
                        dependency_key=str(dependency_key),
                        requirement=requirement,
                        section=section,
                    )
                )
    return sorted(
        requirements,
        key=lambda item: (
            item.package,
            item.root_name,
            item.owner,
            _display(item.manifest_path),
            item.dependency_key,
        ),
    )


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int


@dataclass(frozen=True)
class Bound:
    version: Version
    inclusive: bool


@dataclass(frozen=True)
class VersionRange:
    lower: Bound | None
    upper: Bound | None


def _parse_version(value: str) -> Version | None:
    core = value.strip().split("-", 1)[0].split("+", 1)[0]
    if not core:
        return None
    parts = core.split(".")
    if not 1 <= len(parts) <= 3:
        return None
    ints: list[int] = []
    for part in parts:
        if part in {"*", "x", "X"}:
            break
        if not part.isdigit():
            return None
        ints.append(int(part))
    while len(ints) < 3:
        ints.append(0)
    return Version(*ints[:3])


def _compatibility_upper(version: Version) -> Version:
    if version.major > 0:
        return Version(version.major + 1, 0, 0)
    if version.minor > 0:
        return Version(0, version.minor + 1, 0)
    return Version(0, 0, version.patch + 1)


def _compatibility_key(version: Version) -> tuple[int, int | None, int | None]:
    if version.major > 0:
        return version.major, None, None
    if version.minor > 0:
        return 0, version.minor, None
    return 0, 0, version.patch


def _merge_ranges(left: VersionRange, right: VersionRange) -> VersionRange:
    lower = left.lower
    if right.lower is not None:
        if lower is None or right.lower.version > lower.version:
            lower = right.lower
        elif right.lower.version == lower.version:
            lower = Bound(lower.version, lower.inclusive and right.lower.inclusive)

    upper = left.upper
    if right.upper is not None:
        if upper is None or right.upper.version < upper.version:
            upper = right.upper
        elif right.upper.version == upper.version:
            upper = Bound(upper.version, upper.inclusive and right.upper.inclusive)
    return VersionRange(lower=lower, upper=upper)


def _range_for_piece(piece: str) -> VersionRange | None:
    piece = piece.strip()
    if not piece or piece == "*":
        return VersionRange(lower=None, upper=None)

    for operator in (">=", "<=", ">", "<", "="):
        if piece.startswith(operator):
            version = _parse_version(piece[len(operator) :].strip())
            if version is None:
                return None
            if operator == ">=":
                return VersionRange(lower=Bound(version, True), upper=None)
            if operator == ">":
                return VersionRange(lower=Bound(version, False), upper=None)
            if operator == "<=":
                return VersionRange(lower=None, upper=Bound(version, True))
            if operator == "<":
                return VersionRange(lower=None, upper=Bound(version, False))
            return VersionRange(
                lower=Bound(version, True),
                upper=Bound(version, True),
            )

    if piece.startswith("^"):
        version = _parse_version(piece[1:].strip())
        if version is None:
            return None
        return VersionRange(
            lower=Bound(version, True),
            upper=Bound(_compatibility_upper(version), False),
        )

    if piece.startswith("~"):
        version = _parse_version(piece[1:].strip())
        if version is None:
            return None
        upper = Version(version.major + 1, 0, 0) if "." not in piece[1:] else Version(version.major, version.minor + 1, 0)
        return VersionRange(lower=Bound(version, True), upper=Bound(upper, False))

    if "*" in piece or "x" in piece or "X" in piece:
        prefix = piece.replace("x", "*").replace("X", "*").split("*", 1)[0].rstrip(".")
        version = _parse_version(prefix)
        if version is None:
            return VersionRange(lower=None, upper=None)
        parts = prefix.split(".") if prefix else []
        if len(parts) <= 1:
            upper = Version(version.major + 1, 0, 0)
        elif len(parts) == 2:
            upper = Version(version.major, version.minor + 1, 0)
        else:
            upper = Version(version.major, version.minor, version.patch + 1)
        return VersionRange(lower=Bound(version, True), upper=Bound(upper, False))

    version = _parse_version(piece)
    if version is None:
        return None
    return VersionRange(
        lower=Bound(version, True),
        upper=Bound(_compatibility_upper(version), False),
    )


def parse_requirement(requirement: str) -> VersionRange | None:
    current = VersionRange(lower=None, upper=None)
    for piece in requirement.split(","):
        parsed = _range_for_piece(piece)
        if parsed is None:
            return None
        current = _merge_ranges(current, parsed)
    return current


def _satisfies(version: Version, version_range: VersionRange) -> bool:
    lower = version_range.lower
    if lower is not None:
        if version < lower.version or (version == lower.version and not lower.inclusive):
            return False
    upper = version_range.upper
    if upper is not None:
        if version > upper.version or (version == upper.version and not upper.inclusive):
            return False
    return True


def is_candidate_convergence_conflict(selected_version: str, requirement: str) -> bool:
    selected = _parse_version(selected_version)
    version_range = parse_requirement(requirement)
    if selected is None or version_range is None or version_range.lower is None:
        return False
    lower_key = _compatibility_key(version_range.lower.version)
    if _compatibility_key(selected) != lower_key:
        return False
    return not _satisfies(selected, version_range)


def build_report(
    roots: list[RootSpec],
    manifest_globs: tuple[str, ...],
    package_filter: set[str] | None = None,
) -> dict[str, Any]:
    locked_packages: list[LockedPackage] = []
    requirements: list[Requirement] = []
    for root in roots:
        locked_packages.extend(parse_lockfile(root))
        requirements.extend(parse_manifest_requirements(root, manifest_globs))
    if package_filter:
        locked_packages = [locked for locked in locked_packages if locked.package in package_filter]
        requirements = [requirement for requirement in requirements if requirement.package in package_filter]

    by_package: dict[str, list[LockedPackage]] = {}
    for locked in locked_packages:
        by_package.setdefault(locked.package, []).append(locked)

    mismatches: list[dict[str, Any]] = []
    for requirement in requirements:
        for locked in by_package.get(requirement.package, []):
            if not is_candidate_convergence_conflict(locked.version, requirement.requirement):
                continue
            mismatches.append(
                {
                    "package": requirement.package,
                    "dependency_key": requirement.dependency_key,
                    "dependency_owner": requirement.owner,
                    "requirement": requirement.requirement,
                    "requirement_section": requirement.section,
                    "manifest_root": requirement.root_name,
                    "manifest_path": _display(requirement.manifest_path),
                    "selected_root": locked.root_name,
                    "selected_lockfile": _display(locked.lockfile_path),
                    "selected_version": locked.version,
                }
            )

    mismatches.sort(
        key=lambda item: (
            item["package"],
            item["selected_version"],
            item["selected_root"],
            item["manifest_root"],
            item["dependency_owner"],
        )
    )
    verdict = "FAIL" if mismatches else "PASS"
    return {
        "schema_version": SCHEMA_VERSION,
        "verdict": verdict,
        "roots": [{"name": root.name, "path": _display(root.path)} for root in roots],
        "manifest_globs": list(manifest_globs),
        "package_filter": sorted(package_filter or []),
        "summary": {
            "root_count": len(roots),
            "lockfile_package_count": len(locked_packages),
            "manifest_requirement_count": len(requirements),
            "mismatch_count": len(mismatches),
        },
        "mismatches": mismatches,
        "next_action": (
            "Align the selected Cargo.lock package version with the highest same-lane requirement "
            "before launching the RCH validation."
            if mismatches
            else "No same-lane locked dependency convergence blockers detected."
        ),
    }


def render_human(report: dict[str, Any]) -> str:
    lines = [
        f"rch dependency convergence preflight: {report['verdict']}",
        f"roots: {report['summary']['root_count']}",
        f"manifest_requirements: {report['summary']['manifest_requirement_count']}",
        f"lockfile_packages: {report['summary']['lockfile_package_count']}",
        f"mismatches: {report['summary']['mismatch_count']}",
    ]
    if report["mismatches"]:
        lines.append("blocked requirements:")
        for mismatch in report["mismatches"]:
            lines.append(
                "- "
                f"{mismatch['package']} selected {mismatch['selected_version']} "
                f"from {mismatch['selected_root']}:{mismatch['selected_lockfile']} "
                f"does not satisfy {mismatch['requirement']} required by "
                f"{mismatch['dependency_owner']} ({mismatch['manifest_path']})"
            )
    lines.append(f"next_action: {report['next_action']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Root spec NAME=PATH or PATH. May be repeated. Defaults to franken_node=<repo root>.",
    )
    parser.add_argument(
        "--manifest-glob",
        action="append",
        default=[],
        help="Cargo.toml glob relative to each root; defaults to workspace-level package globs.",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Limit checks to this package name; may be repeated.",
    )
    parser.add_argument(
        "--fail-exit-code",
        type=int,
        default=DEFAULT_FAIL_EXIT_CODE,
        help="exit code used when convergence mismatches are detected",
    )
    args = parser.parse_args(argv)

    root_values = args.root or [f"franken_node={ROOT}"]
    roots = [parse_root_spec(value) for value in root_values]
    manifest_globs = tuple(args.manifest_glob or DEFAULT_MANIFEST_GLOBS)

    report = build_report(roots, manifest_globs, set(args.package))
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render_human(report), end="")
    return int(args.fail_exit_code) if report["mismatches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
