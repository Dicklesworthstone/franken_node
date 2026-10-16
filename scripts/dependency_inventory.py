"""Bounded npm/Bun/pnpm/Yarn inventory for the migration project scanner.

Read-only metadata analysis, not package installation, provenance verification,
version-range satisfaction, or proof of the actual node_modules contents. Each
lockfile location remains a separate observation, including duplicate versions.
Spec: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/
      https://bun.com/reference/bun/BunLockFile
"""
from __future__ import annotations

import json
from fnmatch import fnmatchcase
import os
from pathlib import Path
import re
import stat

MAX_MANIFEST_BYTES = 512 * 1024
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 50_000
MAX_DEPTH = 64
SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
MAX_WORKSPACES = 1024
MAX_WORKSPACE_ENTRIES = 100_000
MAX_DEPENDENCY_EDGES = 100_000
WORKSPACE_EXCLUSIONS = frozenset({"node_modules", ".git", ".beads", ".franken-node",
                                  ".migrate-backup", ".franken-rewrite"})


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


def _jsonc(raw: bytes) -> bytes:
    """Remove only JSON comments/trailing commas; never evaluate lock text.

    Both passes are linear and preserve quoted bytes. Invalid UTF-8, excessive
    nesting, unterminated comments/strings, duplicate keys and all other JSON
    extensions remain errors. Comment bytes still consume the capture budget.
    """
    raw.decode("utf-8-sig")
    data = bytearray(raw)
    index, depth, quoted = 0, 0, False
    while index < len(data):
        char = data[index]
        if quoted:
            if char == 92:
                index += 2
                continue
            if char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char == 47 and data[index:index + 2] == b"//":
            end = index + 2
            while end < len(data) and data[end] not in (10, 13):
                end += 1
            data[index:end] = b" " * (end - index)
            index = end
            continue
        elif char == 47 and data[index:index + 2] == b"/*":
            end = data.find(b"*/", index + 2)
            if end < 0:
                raise InventoryError("unterminated Bun lockfile comment")
            end += 2
            data[index:end] = b" " * (end - index)
            index = end
            continue
        elif char in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise InventoryError("Bun lockfile nesting exceeds inventory limit")
        elif char in (93, 125):
            depth -= 1
        index += 1
    if quoted:
        raise InventoryError("unterminated Bun lockfile string")
    index, previous, comma, quoted = 0, None, None, False
    while index < len(data):
        char = data[index]
        if quoted:
            if char == 92:
                index += 2
                continue
            if char == 34:
                quoted = False
                previous = char
        elif char == 34:
            quoted, comma = True, None
        elif char not in (9, 10, 13, 32):
            if char in (93, 125) and comma is not None:
                data[comma] = 32
            # Do not turn [,] or {"key":,} into valid empty containers.
            comma = index if char == 44 and previous not in (None, 44, 58, 91, 123) else None
            previous = char
        index += 1
    return bytes(data)


def _read(path: Path, limit: int, *, budget: list[int] | None = None, jsonc: bool = False):
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
    if budget is not None:
        budget[0] -= len(raw)
        if budget[0] < 0:
            raise InventoryError("workspace metadata exceeds aggregate byte limit")
    try:
        value = json.loads(_jsonc(raw) if jsonc else raw,
                           object_pairs_hook=_unique, parse_constant=_constant)
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


def _workspace_states(pattern: tuple[str, ...], parts: tuple[str, ...]) -> set[int]:
    """Component glob matching with **, also used to prune unrelated subtrees."""
    def closure(states):
        result = set(states)
        for index in range(len(pattern)):
            if index in result and pattern[index] == "**":
                result.add(index + 1)
        return result
    states = closure({0})
    for part in parts:
        following = set()
        for index in states:
            if index == len(pattern):
                continue
            if pattern[index] == "**":
                following.add(index)
            elif fnmatchcase(part, pattern[index]):
                following.add(index + 1)
        states = closure(following)
    return states


def _workspace_manifests(project: Path, package: dict, *, bun: bool = False) -> list[tuple[str, dict]]:
    """Read explicitly selected workspace manifests, never installed packages.

    Exact paths, component * globs and ** directory globs are supported. Other
    glob dialects fail explicitly instead of silently omitting a workspace.
    No filesystem symlinks are followed, even when their target is contained.
    """
    raw = package.get("workspaces", [])
    if bun and isinstance(raw, dict):
        # Bun's catalog-capable form still selects only these directory globs.
        # Catalog values are interpreted by the Bun inventory, not the walker.
        raw = raw.get("packages")
    if not isinstance(raw, list) or len(raw) > MAX_WORKSPACES:
        raise InventoryError("workspaces must be a bounded array of relative directory patterns")
    patterns = []
    for value in raw:
        value = _path(value)
        parts = tuple(value.split("/"))
        if (any(char in value for char in "!?[]{}()")
                or any("**" in part and part != "**" for part in parts)
                or set(parts) & WORKSPACE_EXCLUSIONS):
            raise InventoryError("unsupported workspace pattern; use relative paths, * or ** components")
        patterns.append(parts)
    if not patterns:
        return []
    pending = [(project, ())]
    result, names = {}, {}
    budget = [MAX_LOCK_BYTES]
    entries_seen = 0
    while pending:
        directory, parts = pending.pop()
        if len(parts) > MAX_DEPTH:
            raise InventoryError("workspace traversal exceeds depth limit")
        states = [_workspace_states(pattern, parts) for pattern in patterns]
        if parts and any(len(pattern) in state for pattern, state in zip(patterns, states)):
            relative = "/".join((*parts, "package.json"))
            manifest = _read(project / relative, min(MAX_MANIFEST_BYTES, budget[0]), budget=budget)
            if manifest is not None:
                name = _name(manifest.get("name"))
                if name in names and names[name] != relative:
                    raise InventoryError("duplicate workspace package name")
                names[name] = relative
                result[relative] = manifest
                if len(result) > MAX_WORKSPACES:
                    raise InventoryError("workspace count exceeds inventory limit")
        # An exact match does not authorize recursion below that directory.
        if not any(any(index < len(pattern) for index in state)
                   for pattern, state in zip(patterns, states)):
            continue
        with os.scandir(directory) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_WORKSPACE_ENTRIES:
                    raise InventoryError("workspace traversal exceeds entry limit")
                if entry.name in WORKSPACE_EXCLUSIONS:
                    continue
                child = (*parts, entry.name)
                if not any(_workspace_states(pattern, child) for pattern in patterns):
                    continue
                if entry.is_symlink():
                    raise InventoryError("workspace traversal cannot follow symlinks")
                if entry.is_dir(follow_symlinks=False):
                    pending.append((Path(entry.path), child))
    return sorted(result.items())


def _locked_from_workspace(directory: str, name: str, locations: dict[str, dict]) -> dict | None:
    # Resolve only the recorded install location. This does NOT prove a
    # semver range is satisfied or that the package is present on disk.
    parts = directory.split("/") if directory else []
    for length in range(len(parts), -1, -1):
        candidate = "/".join([*parts[:length], "node_modules", name])
        if candidate in locations:
            return locations[candidate]
    return None


def _bun_parts(key: str) -> list[str]:
    """Bun keys are logical dependency chains, not isolated-store disk paths."""
    parts, names, index = _path(key).split("/"), [], 0
    while index < len(parts):
        width = 2 if parts[index].startswith("@") else 1
        names.append(_name("/".join(parts[index:index + width])))
        index += width
        if len(names) > MAX_DEPTH:
            raise InventoryError("Bun package chain exceeds inventory depth")
    return names


def _bun_lookup(scope: list[str], name: str, locations: dict[str, dict]) -> dict | None:
    for count in range(len(scope), -1, -1):
        found = locations.get("/".join([*scope[:count], name]))
        if found is not None:
            return found
    return None


def _bun_inventory(lock: dict, native: set[str], manifests: dict[str, dict]) -> list[dict]:
    """Observe Bun v1/v2 metadata without installing, approving, or executing.

    Registry tuples supply pinned identities, not authenticated content. Local,
    git and patched resolutions require review. Logical keys stay verbatim and
    are explicitly labelled: they are NOT paths into Bun's isolated store.
    Workspace declarations absent from the captured source tree remain visible
    as lockfile observations, never as fabricated reads of package.json.
    """
    if type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] not in (1, 2):
        raise InventoryError("unsupported Bun lockfileVersion (expected 1 or 2)")
    if type(lock.get("configVersion", 0)) is not int or lock.get("configVersion", 0) not in (0, 1):
        raise InventoryError("unsupported Bun configVersion")
    packages, workspaces = lock.get("packages"), lock.get("workspaces")
    if not isinstance(packages, dict) or len(packages) > MAX_PACKAGES:
        raise InventoryError("Bun lockfile needs a bounded packages object")
    if (not isinstance(workspaces, dict) or "" not in workspaces
            or len(workspaces) > MAX_WORKSPACES + 1):
        raise InventoryError("Bun lockfile needs a bounded workspaces object with a root")
    workspace_names = {}
    for directory, record in workspaces.items():
        if directory:
            _path(directory)
        if not isinstance(record, dict):
            raise InventoryError("invalid Bun workspace descriptor")
        if directory:
            name = _name(record.get("name"))
            if name in workspace_names:
                raise InventoryError("duplicate Bun workspace name")
            workspace_names[name] = directory
        _declarations(record)

    def request_map(value):
        if not isinstance(value, dict) or len(value) > MAX_PACKAGES:
            raise InventoryError("invalid Bun dependency mapping")
        return {_name(name): _string(request, "Bun dependency request") for name, request in value.items()}

    def catalog_maps(metadata, *, lockfile=False):
        nested = metadata.get("workspaces")
        if not lockfile and isinstance(nested, dict) and ("catalog" in nested or "catalogs" in nested):
            if "catalog" in metadata or "catalogs" in metadata:
                raise InventoryError("ambiguous top-level and workspace Bun catalogs")
            metadata = nested
        default = request_map(metadata.get("catalog", {}))
        named = metadata.get("catalogs", {})
        if not isinstance(named, dict) or len(named) > MAX_WORKSPACES:
            raise InventoryError("invalid Bun catalogs")
        named = {_string(name, "catalog name"): request_map(values) for name, values in named.items()}
        if default.keys() & named.get("default", {}).keys():
            raise InventoryError("overlapping default Bun catalogs")
        default.update(named.get("default", {}))
        named["default"] = default
        return named

    locked_catalogs = catalog_maps(lock, lockfile=True)
    current_catalogs = catalog_maps(manifests["package.json"]) if "package.json" in manifests else locked_catalogs
    overrides = lock.get("overrides", {})
    patches = {}
    for kind, mapping in (("overrides", overrides), ("patches", lock.get("patchedDependencies", {})),
                          ("patches", manifests.get("package.json", {}).get("patchedDependencies", {}))):
        if not isinstance(mapping, dict) or len(mapping) > MAX_PACKAGES:
            raise InventoryError("invalid Bun override/patch mapping")
        for name, value in mapping.items():
            _string(name, "Bun override/patch key")
            _string(value, "Bun override/patch value")
        if kind == "patches":
            patches.update(mapping)
    trusted = set()
    for metadata in (lock, manifests.get("package.json", {})):
        names = metadata.get("trustedDependencies", [])
        if not isinstance(names, list) or len(names) > MAX_PACKAGES:
            raise InventoryError("invalid Bun trustedDependencies")
        trusted.update(_name(name) for name in names)
    rows, locations, edges = [], {}, []
    edge_count = 0

    def add_edges(source, scope, record, force_review=False):
        nonlocal edge_count
        declarations = _declarations(record)
        edge_count += len(declarations)
        if edge_count > MAX_DEPENDENCY_EDGES:
            raise InventoryError("Bun dependency edges exceed inventory limit")
        edges.append((source, scope, declarations, force_review))

    def note(row, text):
        row["notes"] = "; ".join(filter(None, (row["notes"], text)))
        if row["risk_level"] == "low":
            row["risk_level"] = "high"

    for key, values in sorted(packages.items()):
        parts = _bun_parts(key)
        if not isinstance(values, list) or not values:
            raise InventoryError("invalid Bun package tuple")
        identity = _string(values[0], "Bun package identity")
        separator = identity.find("@", 1)
        if separator < 1:
            raise InventoryError("Bun package identity needs a name and resolution")
        name, resolution = _name(identity[:separator]), _string(identity[separator + 1:], "Bun resolution")
        info, linked, kind, version = {}, False, "external", resolution
        if len(values) == 4:
            if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", resolution)
                    or not isinstance(values[1], str) or not isinstance(values[3], str)):
                raise InventoryError("invalid Bun registry tuple")
            for field in (values[1], values[3]):
                if field:
                    _string(field, "Bun registry/integrity")
            info, kind = values[2], "registry"
        elif len(values) == 1 and resolution.startswith("workspace:"):
            directory = _path(resolution[len("workspace:"):])
            info = workspaces.get(directory)
            if not isinstance(info, dict) or info.get("name") != name:
                raise InventoryError("Bun workspace link has no matching lockfile descriptor")
            linked, kind, version = True, "workspace", info.get("version")
            if version is not None:
                _string(version, "workspace version")
        elif len(values) == 2 and not resolution.startswith("workspace:"):
            info = values[1]
            linked = resolution.startswith(("file:", "link:", "root:"))
            kind = "local" if linked else "external"
        elif len(values) == 3 and resolution.startswith(("git+", "git:", "git@", "github:", "ssh:")):
            info = values[1]
            _string(values[2], "Bun git tag")
            kind = "git"
        else:
            raise InventoryError("unsupported Bun package tuple")
        if not isinstance(info, dict):
            raise InventoryError("invalid Bun package info")
        _declarations(info)
        row = _row(name, version, native, source="bun.lock", location=key,
                   install=_bool(info, "hasInstallScript"), linked=linked, alias=parts[-1])
        row.update({"location_kind": "bun-logical", "resolution_kind": kind,
                    "explicitly_trusted": name in trusted or parts[-1] in trusted})
        if kind == "registry":
            row["integrity"] = values[3] or None
            if not values[3]:
                note(row, "Registry record has no integrity; content is unverified")
        else:
            note(row, "Non-registry resolution requires content review; no target was opened")
        # Absence here is NOT a claim that Bun's default trust list or external
        # configuration prevents scripts. Only explicit captured trust is known.
        if row["explicitly_trusted"]:
            note(row, "Bun explicitly allows install scripts; their presence/execution is unverified")
        if identity in patches:
            note(row, "Bun patch changes package content; patch contents are unverified")
            row["patch_reference"] = patches[identity]
        for flag in ("os", "cpu", "optionalPeers"):
            if flag not in info:
                continue
            value = info[flag]
            if flag == "optionalPeers" and not isinstance(value, list):
                raise InventoryError("Bun optionalPeers must be an array")
            sequence = value if isinstance(value, list) else [value]
            if len(sequence) > MAX_PACKAGES:
                raise InventoryError("Bun platform/peer metadata exceeds inventory limit")
            for entry in sequence:
                _string(entry, "Bun platform/peer constraint")
            row[flag] = value
        rows.append(row)
        locations[key] = row
        if kind != "workspace":
            add_edges(f"bun.lock#packages/{key}", parts, info)
    # Keep workspace requests even when no corresponding source manifest was
    # provided. Captured current declarations take precedence over stale lock
    # declarations for that same source, but never assert range satisfaction.
    for directory, record in sorted(workspaces.items()):
        source = f"{directory}/package.json" if directory else "package.json"
        if source not in manifests:
            scope = [_name(record.get("name"))] if directory else []
            add_edges(f"bun.lock#workspaces/{directory}", scope, record)
    for source, record in sorted(manifests.items()):
        directory = source.rpartition("/")[0]
        workspace = workspaces.get(directory)
        scope = []
        if directory and workspace is not None:
            if record.get("name") != workspace.get("name"):
                raise InventoryError("captured workspace identity differs from Bun lockfile")
            scope = [_name(record.get("name"))]
        add_edges(source, scope, record)
    # Overrides may name an alias to a new native package even while every
    # ordinary declaration still matches an old pure-JS lock record. Retain
    # those requests as review items; do not implement package installation or
    # pretend the old lock satisfies the override's range/target.
    for source, metadata in (("bun.lock#overrides", lock),
                             ("package.json#overrides", manifests.get("package.json", {}))):
        mapping = metadata.get("overrides", {})
        if not isinstance(mapping, dict) or len(mapping) > MAX_PACKAGES:
            raise InventoryError("invalid Bun overrides")
        requests = {}
        for selector, request in mapping.items():
            selector = _string(selector, "Bun override selector")
            separator = selector.find("@", 1)
            name = _name(selector if separator < 0 else selector[:separator])
            if name in requests:
                raise InventoryError("ambiguous multiple Bun override selectors for one package")
            requests[name] = _string(request, "Bun override request")
        add_edges(source, [], {"dependencies": requests}, True)
    for source, scope, declarations, force_review in edges:
        for installed_as, (request, section) in sorted(declarations.items()):
            if request.startswith("catalog:"):
                if source.startswith("bun.lock#packages/"):
                    raise InventoryError("published Bun package cannot depend on a workspace catalog")
                label = request[len("catalog:"):].strip() or "default"
                catalogs = locked_catalogs if source.startswith("bun.lock#") else current_catalogs
                request = catalogs.get(label, {}).get(installed_as)
                if request is None or request.startswith("catalog:"):
                    raise InventoryError("Bun catalog request has no concrete declaration")
            name, version = _alias(installed_as, request)
            locked = _bun_lookup(scope, installed_as, locations)
            if not force_review and locked is not None and locked["name"] == name:
                continue
            row = _row(name, version, native, source=source, location=None,
                       unresolved=True, alias=installed_as)
            row.update({"dependency_kind": section, "declared_in": source})
            if force_review:
                row["notes"] = "Override target/range requires review; lock satisfaction is unverified"
                if row["has_native_addon"]:
                    row["notes"] += "; Native addon - requires port or replacement"
            rows.append(row)
            if len(rows) > MAX_PACKAGES:
                raise InventoryError("dependency count exceeds inventory limit")
    return rows


def scan_dependencies(project: Path, native: set[str], *,
                      additional_manifests: dict[str, dict] | None = None) -> list[dict]:
    """Inventory all locked locations, retaining unresolved root declarations.

    Lockfile v2's legacy projection is never unioned with its packages table.
    Both npm lock filenames are accepted individually; coexistence is rejected
    because their precedence differs between npm <=11 and npm >=12. No hidden
    node_modules lock, external link, registry, or package manager is consulted.
    Bun text v1/v2 uses bounded JSONC capture and logical package observations.
    Mixed-manager locks and binary bun.lockb fail rather than hiding dependency
    risk. This reader never converts or deletes a lockfile.

    A captured-project assessor may supply additional project-relative manifests
    it already read, preserving its broader non-workspace package coverage. The
    caller owns their byte budget; conflicting observations are never merged.
    """
    project = Path(project)
    paths = [project / name for name in ("package-lock.json", "npm-shrinkwrap.json", "bun.lock", "bun.lockb", "pnpm-lock.yaml", "yarn.lock")
             if os.path.lexists(project / name)]
    if len(paths) > 1:
        raise InventoryError("multiple lockfiles exist; select one authoritative inventory explicitly")
    if paths and paths[0].name == "yarn.lock":
        if __package__:
            from .yarn_dependency_inventory import scan_yarn_dependencies
        else:
            from yarn_dependency_inventory import scan_yarn_dependencies
        return scan_yarn_dependencies(project, native, additional_manifests=additional_manifests)
    if paths and paths[0].name == "pnpm-lock.yaml":
        if __package__:
            from .pnpm_dependency_inventory import scan_pnpm_dependencies
        else:
            from pnpm_dependency_inventory import scan_pnpm_dependencies
        return scan_pnpm_dependencies(project, native, additional_manifests=additional_manifests)
    bun = bool(paths and paths[0].name == "bun.lock")
    package = _read(project / "package.json", MAX_MANIFEST_BYTES)
    manifests = dict([("package.json", package or {}), *_workspace_manifests(project, package or {}, bun=bun)])
    if additional_manifests is not None:
        if not isinstance(additional_manifests, dict) or len(additional_manifests) > MAX_WORKSPACES + 1:
            raise InventoryError("additional manifests exceed inventory limit")
        for source, manifest in additional_manifests.items():
            _path(source)
            if source.split("/")[-1] != "package.json" or not isinstance(manifest, dict):
                raise InventoryError("additional manifest must be a project package.json object")
            if source in manifests and manifests[source] != manifest:
                raise InventoryError("manifest changed between captured observations")
            manifests[source] = manifest
        if len(manifests) > MAX_WORKSPACES + 1:
            raise InventoryError("combined manifest count exceeds inventory limit")
    rows, roots = [], set()
    if paths:
        if paths[0].name == "bun.lockb":
            raise InventoryError("binary bun.lockb is unsupported; supply a reviewed text bun.lock")
        lock = _read(paths[0], MAX_LOCK_BYTES, jsonc=paths[0].name == "bun.lock")
        if lock is None:
            raise InventoryError("selected lockfile disappeared")
        if paths[0].name == "bun.lock":
            root_captured = package is not None or (additional_manifests is not None
                                                    and "package.json" in additional_manifests)
            rows = _bun_inventory(lock, native, manifests if root_captured else {
                source: manifest for source, manifest in manifests.items() if source != "package.json"})
            return sorted(rows, key=lambda row: (row["name"], row["version"] or "",
                                                row["package_path"] or "", row["source"]))
        else:
            version = lock.get("lockfileVersion")
            if type(version) is not int or version not in (1, 2, 3):
                raise InventoryError("unsupported npm lockfileVersion (expected 1, 2 or 3)")
            rows, roots = (_legacy if version == 1 else _modern)(lock, paths[0].name, native)
    locations = {row["package_path"]: row for row in rows}
    for source, manifest in sorted(manifests.items()):
        directory = source.rpartition("/")[0]
        for installed_as, (request, section) in sorted(_declarations(manifest).items()):
            name, version = _alias(installed_as, request)
            locked = _locked_from_workspace(directory, installed_as, locations)
            # A previous package at the same alias/location cannot hide a
            # newly declared package identity. A matching name still makes no
            # claim that the recorded version satisfies the requested range.
            if locked is not None and locked["name"] == name:
                continue
            row = _row(name, version, native, source=source, location=None,
                       unresolved=bool(paths), alias=installed_as)
            row["dependency_kind"] = section
            row["declared_in"] = source
            if locked is not None:
                row["notes"] = (row["notes"] or "") + "; locked package identity differs from declaration"
            rows.append(row)
            if len(rows) > MAX_PACKAGES:
                raise InventoryError("dependency count exceeds inventory limit")
    if len(rows) > MAX_PACKAGES:
        raise InventoryError("dependency count exceeds inventory limit")
    return sorted(rows, key=lambda row: (row["name"], row["version"] or "",
                                        row["package_path"] or "", row["source"]))
