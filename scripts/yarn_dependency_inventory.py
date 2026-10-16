"""Read-only Yarn lock inventory used by the existing migration scanner.

Classic format: https://classic.yarnpkg.com/en/docs/yarn-lock
Logical descriptors are NOT installed paths. This never installs dependencies,
executes PnP loaders/hooks, fetches archives, verifies semver/integrity, or admits
native execution. Missing edges remain visible, including optional dependencies.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

if __package__:
    from . import dependency_inventory as core
else:
    import dependency_inventory as core

MAX_LINES = 500_000
MAX_TOKENS = 1_000_000
CLASSIC_HEADER = "# yarn lockfile v1"
CLASSIC_FIELDS = frozenset({"version", "resolved", "integrity", "dependencies",
                            "optionalDependencies", "prebuiltVariants", "uid", "registry"})


def _raw(path: Path, limit: int) -> bytes | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not hasattr(os, "O_NOFOLLOW"):
        raise core.InventoryError("Yarn capture requires no-follow filesystem access")
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise core.InventoryError("Yarn metadata must be a bounded regular file")
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if identity(opened) != identity(before) or not stat.S_ISREG(opened.st_mode):
            raise core.InventoryError("Yarn metadata changed before capture")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(raw) > limit or len(raw) != before.st_size or identity(after) != identity(before)
            or identity(after) != identity(path.lstat())):
        raise core.InventoryError("Yarn metadata changed during capture")
    return raw


def _text(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as error:
        raise core.InventoryError("Yarn lockfile must be UTF-8") from error
    if any(ord(ch) < 32 and ch not in "\r\n" for ch in text):
        raise core.InventoryError("unsupported control character in Yarn lockfile")
    return text


def _atom(text: str, position: int) -> tuple[str, int]:
    """One Classic string, with JSON escapes only inside double quotes."""
    if position >= len(text):
        raise core.InventoryError("missing Yarn lockfile token")
    if text[position] == '"':
        try:
            value, count = json.JSONDecoder().raw_decode(text[position:])
        except (ValueError, RecursionError) as error:
            raise core.InventoryError("invalid quoted Yarn lockfile token") from error
        return core._string(value, "Yarn lockfile token"), position + count
    end = position
    while end < len(text) and text[end] not in " ,":
        end += 1
    value = text[position:end]
    if not value or value[0] in "'&*!|>{[\"" or value in ("---", "...", "<<"):
        raise core.InventoryError("unsupported Yarn lockfile token")
    return core._string(value, "Yarn lockfile token"), end


def _classic(raw: bytes) -> list[tuple[list[str], dict]]:
    text = _text(raw)
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise core.InventoryError("Yarn lockfile line budget exceeded")
    if CLASSIC_HEADER not in lines:
        raise core.InventoryError("unsupported Yarn lockfile format; expected Classic v1")
    records, record, child = [], None, None
    tokens = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        tokens += 1
        if tokens > MAX_TOKENS:
            raise core.InventoryError("Yarn lockfile token budget exceeded")
        indent = len(line) - len(line.lstrip(" "))
        value = line[indent:]
        if indent == 0:
            if not value.endswith(":"):
                raise core.InventoryError("Yarn package group must end in a colon")
            group, position, descriptors = value[:-1], 0, []
            while position < len(group):
                name, position = _atom(group, position)
                descriptors.append(name)
                tokens += 1
                if tokens > MAX_TOKENS or len(descriptors) > core.MAX_DEPENDENCY_EDGES:
                    raise core.InventoryError("Yarn descriptor budget exceeded")
                if position == len(group):
                    break
                if group[position:position + 2] != ", ":
                    raise core.InventoryError("invalid Yarn descriptor separator")
                position += 2
                if position >= len(group):
                    raise core.InventoryError("empty Yarn descriptor")
            if not descriptors:
                raise core.InventoryError("empty Yarn package group")
            record, child = {}, None
            records.append((descriptors, record))
            if len(records) > core.MAX_PACKAGES:
                raise core.InventoryError("Yarn package budget exceeded")
        elif indent in (2, 4) and record is not None:
            target = record if indent == 2 else child
            if target is None:
                raise core.InventoryError("unattached Yarn dependency map")
            if indent == 2 and value.endswith(":"):
                key, end = _atom(value[:-1], 0)
                if end != len(value) - 1 or key in target:
                    raise core.InventoryError("invalid or duplicate Yarn lockfile field")
                child = {}
                target[key] = child
                continue
            key, end = _atom(value, 0)
            if end >= len(value) or value[end] != " ":
                raise core.InventoryError("missing Yarn field value")
            while end < len(value) and value[end] == " ":
                end += 1
            item, end = _atom(value, end)
            if value[end:].strip() and not value[end:].startswith(" #"):
                raise core.InventoryError("unsupported trailing Yarn field syntax")
            if key in target:
                raise core.InventoryError("duplicate Yarn lockfile field")
            target[key] = item
            if indent == 2:
                child = None
        else:
            raise core.InventoryError("unsupported Yarn lockfile indentation")
    return records


def _descriptor(value: str) -> tuple[str, str]:
    value = core._string(value, "Yarn descriptor")
    separator = value.find("@", 1)
    if separator < 1:
        raise core.InventoryError("Yarn descriptor requires name and request")
    return core._name(value[:separator]), core._string(value[separator + 1:], "Yarn request")


def _mapping(value, label: str) -> dict:
    if not isinstance(value, dict) or len(value) > core.MAX_PACKAGES:
        raise core.InventoryError(f"Yarn {label} must be a bounded mapping")
    return value


def _review(row: dict, message: str) -> None:
    row["notes"] = "; ".join(filter(None, (row["notes"], message)))
    if row["risk_level"] == "low":
        row["risk_level"] = "high"


def _manifests(project: Path, additional) -> dict[str, dict]:
    package = core._read(project / "package.json", core.MAX_MANIFEST_BYTES)
    manifests = {} if package is None else {"package.json": package}
    if additional is not None:
        if not isinstance(additional, dict) or len(additional) > core.MAX_WORKSPACES + 1:
            raise core.InventoryError("additional Yarn manifests exceed inventory limit")
        for source, manifest in additional.items():
            core._path(source)
            if source.split("/")[-1] != "package.json" or not isinstance(manifest, dict):
                raise core.InventoryError("additional Yarn manifest must be a package.json object")
            if source in manifests and manifests[source] != manifest:
                raise core.InventoryError("Yarn manifest changed between observations")
            manifests[source] = manifest
    root = manifests.get("package.json", {})
    workspaces = root.get("workspaces", [])
    if isinstance(workspaces, dict):
        if set(workspaces) - {"packages", "nohoist"} or "packages" not in workspaces:
            raise core.InventoryError("unsupported Yarn workspace object")
        nohoist = workspaces.get("nohoist", [])
        if not isinstance(nohoist, list) or len(nohoist) > core.MAX_WORKSPACES:
            raise core.InventoryError("invalid Yarn nohoist patterns")
        for pattern in nohoist:
            core._string(pattern, "Yarn nohoist pattern")
        # Layout is never inferred; nohoist has no effect on logical identities.
        workspaces = workspaces["packages"]
    for source, manifest in core._workspace_manifests(project, {"workspaces": workspaces}):
        if source in manifests and manifests[source] != manifest:
            raise core.InventoryError("Yarn workspace changed between observations")
        manifests[source] = manifest
    if len(manifests) > core.MAX_WORKSPACES + 1:
        raise core.InventoryError("combined Yarn manifest budget exceeded")
    return manifests


def inventory_classic(records, native: set[str], manifests: dict[str, dict]) -> list[dict]:
    rows, selectors, edge_sets = [], {}, []
    edges = 0

    def account():
        nonlocal edges
        edges += 1
        if edges > core.MAX_DEPENDENCY_EDGES:
            raise core.InventoryError("Yarn dependency edge budget exceeded")

    def append(row):
        if len(rows) >= core.MAX_PACKAGES:
            raise core.InventoryError("Yarn inventory row budget exceeded")
        rows.append(row)

    for descriptors, record in records:
        _mapping(record, "package record")
        if set(record) - CLASSIC_FIELDS:
            raise core.InventoryError("unsupported Yarn Classic package metadata")
        parsed = []
        identities = set()
        for descriptor in descriptors:
            account()
            installed_as, request = _descriptor(descriptor)
            actual, _ = core._alias(installed_as, request)
            parsed.append((descriptor, installed_as, request))
            identities.add(actual)
        if len(identities) != 1:
            raise core.InventoryError("Yarn descriptor group has conflicting identities")
        name = identities.pop()
        version = core._string(record.get("version"), "Yarn locked version")
        row = core._row(name, version, native, source="yarn.lock",
                        location=", ".join(sorted(descriptors)))
        row.update(location_kind="yarn-descriptors", lockfile_format="classic-v1",
                   descriptors=sorted(descriptors), install_script_status="not-recorded")
        aliases = sorted({alias for _, alias, _ in parsed if alias != name})
        if aliases:
            row["installed_aliases"] = aliases
        if any(alias in native for _, alias, _ in parsed):
            row["has_native_addon"], row["risk_level"] = True, "critical"
        for field in ("resolved", "integrity", "uid", "registry"):
            if field in record:
                row[field] = core._string(record[field], f"Yarn {field}")
        if "prebuiltVariants" in record:
            variants = _mapping(record["prebuiltVariants"], "prebuilt variants")
            for key, value in variants.items():
                account()
                core._string(key, "Yarn prebuilt key")
                core._string(value, "Yarn prebuilt reference")
            row["prebuilt_variants"] = variants.copy()
            _review(row, "Prebuilt artifacts require review; targets were not opened")
        for _, _, request in parsed:
            if re.match(r"^[a-zA-Z][a-zA-Z+.-]*:", request) and not request.startswith("npm:"):
                row["is_link"] |= request.startswith(("file:", "link:", "workspace:"))
                _review(row, "Non-registry Yarn request; target contents are unverified")
                break
            if "/" in request and not request.startswith("npm:"):
                _review(row, "Custom Yarn resolution; target contents are unverified")
                break
        append(row)
        for descriptor, _, _ in parsed:
            if descriptor in selectors:
                raise core.InventoryError("duplicate Yarn dependency descriptor")
            selectors[descriptor] = row
        edge_sets.append((f"yarn.lock#{row['package_path']}", record,
                          ("dependencies", "optionalDependencies")))
    for source, manifest in sorted(manifests.items()):
        if manifest.get("resolutions"):
            raise core.InventoryError("Yarn resolutions require explicit inventory support")
        edge_sets.append((source, manifest, core.SECTIONS))
    for source, record, sections in edge_sets:
        for section in sections:
            for installed_as, request in _mapping(record.get(section, {}), section).items():
                account()
                installed_as = core._name(installed_as)
                request = core._string(request, "Yarn dependency request")
                name, version = core._alias(installed_as, request)
                selected = selectors.get(f"{installed_as}@{request}")
                if selected is not None and selected["name"] == name:
                    continue
                row = core._row(name, version, native, source=source, location=None,
                                unresolved=True, alias=installed_as)
                row.update(dependency_kind=section, declared_in=source, requested=request,
                           lockfile_format="classic-v1")
                _review(row, "No exact Yarn descriptor; name or version similarity is insufficient")
                append(row)
    return sorted(rows, key=lambda row: (row["name"], row["version"] or "",
                                        row["package_path"] or "", row["source"]))


def scan_yarn_dependencies(project: Path, native: set[str], *, additional_manifests=None):
    project = Path(project)
    if any(os.path.lexists(project / name) for name in (".yarnrc", ".yarnrc.yml")):
        raise core.InventoryError("Yarn configuration requires explicit review; no hook was executed")
    raw = _raw(project / "yarn.lock", core.MAX_LOCK_BYTES)
    if raw is None:
        raise core.InventoryError("selected Yarn lockfile disappeared")
    return inventory_classic(_classic(raw), native, _manifests(project, additional_manifests))
