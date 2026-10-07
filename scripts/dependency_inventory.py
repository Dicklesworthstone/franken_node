"""Bounded npm dependency inventory for the migration project scanner.

Read-only metadata analysis, not package installation, provenance verification,
version-range satisfaction, or proof of the actual node_modules contents. Each
lockfile location remains a separate observation, including duplicate versions.
Spec: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

MAX_MANIFEST_BYTES = 512 * 1024
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 50_000
MAX_DEPTH = 64
SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


class InventoryError(ValueError):
    """Incomplete or ambiguous metadata must not produce a clean inventory."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate dependency metadata key")
        result[key] = value
    return result


def _constant(_value):
    raise InventoryError("non-finite dependency metadata value")


def _read(path: Path, limit: int):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise InventoryError(f"{path.name}: expected a bounded regular metadata file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if (len(raw) > limit or identity(before) != identity(opened)
            or identity(opened) != identity(after) or identity(after) != identity(path.lstat())):
        raise InventoryError(f"{path.name}: metadata changed during capture")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InventoryError(f"{path.name}: invalid dependency JSON") from error
    if not isinstance(value, dict):
        raise InventoryError(f"{path.name}: metadata must be an object")
    return value


def _string(value, what: str) -> str:
    if (not isinstance(value, str) or not value or len(value.encode("utf-8", errors="replace")) > 4096
            or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise InventoryError(f"invalid {what}")
    return value


def _name(value) -> str:
    name = _string(value, "package name")
    parts = name.split("/")
    expected = 2 if name.startswith("@") else 1
    if (len(parts) != expected or any(not p or p in (".", "..") for p in parts)
            or "\\" in name or ":" in name or any(char.isspace() for char in name)
            or (expected == 2 and len(parts[0]) == 1)):
        raise InventoryError("invalid package name")
    return name


def _path(value) -> str:
    path = _string(value, "package location")
    if ("\\" in path or ":" in path
            or any(p in ("", ".", "..") for p in path.split("/"))):
        raise InventoryError("package location must be project-relative and canonical")
    return path


def _bool(record: dict, key: str) -> bool:
    value = record.get(key, False)
    if type(value) is not bool:
        raise InventoryError(f"invalid {key} flag")
    return value


def _alias(name: str, version: str | None) -> tuple[str, str | None]:
    if version is not None and version.startswith("npm:"):
        target = version[4:]
        package, separator, requested = target.rpartition("@")
        if not separator or not package or not requested:
            raise InventoryError("invalid npm alias")
        return _name(package), requested
    return name, version


def _declarations(package: dict) -> dict[str, tuple[str, str]]:
    result = {}
    for section in SECTIONS:
        values = package.get(section, {})
        if not isinstance(values, dict):
            raise InventoryError(f"{section} must be an object")
        for name, version in values.items():
            name = _name(name)
            version = _string(version, "dependency request")
            # optionalDependencies override dependencies, as in npm. Keep the
            # other declarations' identity without converting ranges to pins.
            if name not in result or section == "optionalDependencies":
                result[name] = (version, section)
            if len(result) > MAX_PACKAGES:
                raise InventoryError("dependency count exceeds inventory limit")
    return result


def _row(name: str, version: str | None, native: set[str], *, source: str,
         location: str | None, install: bool = False, linked: bool = False,
         unresolved: bool = False, alias: str | None = None) -> dict:
    native_addon = name in native or (alias is not None and alias in native)
    notes = []
    if native_addon:
        notes.append("Native addon - requires port or replacement")
    if install:
        notes.append("Lockfile declares an install lifecycle script; review code execution before migration")
    if linked:
        notes.append("Local link/workspace metadata; target contents are not authenticated")
    if unresolved:
        notes.append("Declaration/link has no matching root lockfile record; resolution is unverified")
    if alias is not None and alias != name:
        notes.append(f"Installed as npm alias {alias}")
    return {"name": name, "version": version, "has_native_addon": native_addon,
            "risk_level": "critical" if native_addon else "high" if install or unresolved else "low",
            "notes": "; ".join(notes) or None, "source": source,
            "package_path": location, "has_install_script": install,
            "is_link": linked, "resolution_verified": False}


def _modern(lock: dict, source: str, native: set[str]) -> tuple[list[dict], set[str]]:
    packages = lock.get("packages")
    if not isinstance(packages, dict) or len(packages) > MAX_PACKAGES + 1:
        raise InventoryError("modern lockfile needs a bounded packages object")
    if "" in packages and not isinstance(packages[""], dict):
        raise InventoryError("invalid lockfile root record")
    rows, roots = [], set()
    for location, original in sorted(packages.items()):
        if not location:
            continue
        location = _path(location)
        if not isinstance(original, dict):
            raise InventoryError("invalid package descriptor")
        # Workspace source descriptors are reached via their link record. They
        # are not guessed to be packages from a directory basename.
        components = location.split("/")
        if "node_modules" not in components:
            continue
        last = len(components) - 1 - components[::-1].index("node_modules")
        installed_as = _name("/".join(components[last + 1:]))
        if last == 0:
            roots.add(installed_as)
        linked = _bool(original, "link")
        record = original
        unresolved = False
        if linked:
            target = _path(original.get("resolved"))
            record = packages.get(target)
            if record is None:
                record, unresolved = {}, True
            elif not isinstance(record, dict) or _bool(record, "link"):
                raise InventoryError("link must name an ordinary captured package descriptor")
        version = record.get("version")
        if version is not None:
            version = _string(version, "locked version")
        name = _name(record.get("name", installed_as))
        name, version = _alias(name, version)
        row = _row(name, version, native, source=source, location=location,
                   install=_bool(record, "hasInstallScript"), linked=linked,
                   unresolved=unresolved or version is None, alias=installed_as)
        for flag in ("dev", "optional", "devOptional", "inBundle"):
            row[flag] = _bool(record, flag)
        rows.append(row)
    return rows, roots


def _legacy(lock: dict, source: str, native: set[str]) -> tuple[list[dict], set[str]]:
    dependencies = lock.get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise InventoryError("legacy lockfile dependencies must be an object")
    rows, roots = [], set()
    pending = [("", dependencies, 0)]
    while pending:
        parent, children, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise InventoryError("legacy lockfile nesting exceeds inventory limit")
        for installed_as, record in sorted(children.items()):
            installed_as = _name(installed_as)
            if not isinstance(record, dict):
                raise InventoryError("invalid legacy package descriptor")
            if not parent:
                roots.add(installed_as)
            location = f"{parent + '/' if parent else ''}node_modules/{installed_as}"
            _path(location)
            version = _string(record.get("version"), "locked version")
            name, version = _alias(installed_as, version)
            row = _row(name, version, native, source=source, location=location,
                       install=_bool(record, "hasInstallScript"), alias=installed_as)
            for flag in ("dev", "optional", "bundled"):
                row[flag] = _bool(record, flag)
            rows.append(row)
            if len(rows) > MAX_PACKAGES:
                raise InventoryError("dependency count exceeds inventory limit")
            nested = record.get("dependencies", {})
            if not isinstance(nested, dict):
                raise InventoryError("nested dependencies must be an object")
            if nested:
                pending.append((location, nested, depth + 1))
    return rows, roots


def scan_dependencies(project: Path, native: set[str]) -> list[dict]:
    """Inventory all locked locations, retaining unresolved root declarations.

    Lockfile v2's legacy projection is never unioned with its packages table.
    Both npm lock filenames are accepted individually; coexistence is rejected
    because their precedence differs between npm <=11 and npm >=12. No hidden
    node_modules lock, external link, registry, or package manager is consulted.
    """
    project = Path(project)
    package = _read(project / "package.json", MAX_MANIFEST_BYTES)
    declared = _declarations(package or {})
    paths = [project / name for name in ("package-lock.json", "npm-shrinkwrap.json")
             if os.path.lexists(project / name)]
    if len(paths) > 1:
        raise InventoryError("both npm lockfiles exist; select one authoritative inventory explicitly")
    rows, roots = [], set()
    if paths:
        lock = _read(paths[0], MAX_LOCK_BYTES)
        if lock is None:
            raise InventoryError("selected lockfile disappeared")
        version = lock.get("lockfileVersion")
        if type(version) is not int or version not in (1, 2, 3):
            raise InventoryError("unsupported npm lockfileVersion (expected 1, 2 or 3)")
        rows, roots = (_legacy if version == 1 else _modern)(lock, paths[0].name, native)
    for installed_as, (request, section) in sorted(declared.items()):
        if installed_as in roots:
            continue
        name, version = _alias(installed_as, request)
        row = _row(name, version, native, source="package.json", location=None,
                   unresolved=bool(paths), alias=installed_as)
        row["dependency_kind"] = section
        rows.append(row)
    if len(rows) > MAX_PACKAGES:
        raise InventoryError("dependency count exceeds inventory limit")
    return sorted(rows, key=lambda row: (row["name"], row["version"] or "", row["package_path"] or ""))
