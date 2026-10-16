"""Read-only pnpm v9 lock inventory for the existing migration scanner.

Spec: https://github.com/pnpm/spec/blob/master/lockfile/9.0.md
Dependency paths and peer contexts are logical observations, not filesystem
paths. Nothing here installs packages, follows link/tarball targets, executes
hooks, validates semver/SRI, or approves the native migration execution gate.

The YAML reader accepts the single-line scalar/block/flow mapping and sequence
subset emitted in ordinary pnpm locks. Unsupported YAML fails explicitly. It
never evaluates constructors, aliases, tags, merge keys or block scalars.
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

MAX_YAML_NODES = 1_000_000
MAX_YAML_LINES = 500_000
SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
PIN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")


class _Yaml:
    def __init__(self, raw: bytes):
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeError as error:
            raise core.InventoryError("pnpm metadata is not UTF-8") from error
        if any(ord(ch) < 32 and ch not in "\r\n" for ch in text):
            raise core.InventoryError("pnpm YAML contains unsupported control characters")
        self.lines = []
        self.nodes = 0
        for number, line in enumerate(text.splitlines(), 1):
            if number > MAX_YAML_LINES:
                raise core.InventoryError("pnpm YAML line limit exceeded")
            stripped = line.lstrip(" ")
            if not stripped or stripped.startswith("#"):
                continue
            self.lines.append((len(line) - len(stripped), stripped))
        self.index = 0

    def account(self, depth):
        self.nodes += 1
        if self.nodes > MAX_YAML_NODES or depth > core.MAX_DEPTH:
            raise core.InventoryError("pnpm YAML node/depth budget exceeded")

    def inline(self, text, depth=0):
        """Parse flow values with explicit positions; quotes protect delimiters."""
        index = 0

        def spaces():
            nonlocal index
            while index < len(text) and text[index] == " ":
                index += 1

        def value(level, key=False, flow=False):
            nonlocal index
            self.account(level)
            spaces()
            if index >= len(text):
                raise core.InventoryError("missing pnpm YAML value")
            char = text[index]
            if char in "[{" and not key:
                index += 1
                close = "]" if char == "[" else "}"
                result = [] if char == "[" else {}
                spaces()
                if index < len(text) and text[index] == close:
                    index += 1
                    return result
                while True:
                    if char == "[":
                        result.append(value(level + 1, flow=True))
                    else:
                        name = value(level + 1, key=True, flow=True)
                        spaces()
                        if not isinstance(name, str) or name == "<<" or name in result:
                            raise core.InventoryError("invalid or duplicate pnpm YAML mapping key")
                        if index >= len(text) or text[index] != ":":
                            raise core.InventoryError("missing pnpm YAML mapping separator")
                        index += 1
                        result[name] = value(level + 1, flow=True)
                    spaces()
                    if index >= len(text):
                        raise core.InventoryError("unterminated pnpm YAML flow collection")
                    separator = text[index]
                    index += 1
                    if separator == close:
                        return result
                    if separator != ",":
                        raise core.InventoryError("invalid pnpm YAML flow separator")
                    spaces()
                    if index < len(text) and text[index] == close:
                        index += 1
                        return result
            if char == '"':
                try:
                    result, consumed = json.JSONDecoder().raw_decode(text[index:])
                except ValueError as error:
                    raise core.InventoryError("unsupported pnpm YAML quoted scalar") from error
                index += consumed
                if not isinstance(result, str):
                    raise core.InventoryError("invalid pnpm YAML quoted scalar")
            elif char == "'":
                index += 1
                chunks = []
                while index < len(text):
                    end = text.find("'", index)
                    if end < 0:
                        raise core.InventoryError("unterminated pnpm YAML quoted scalar")
                    chunks.append(text[index:end])
                    index = end + 1
                    if index < len(text) and text[index] == "'":
                        chunks.append("'")
                        index += 1
                    else:
                        break
                else:
                    raise core.InventoryError("unterminated pnpm YAML quoted scalar")
                result = "".join(chunks)
            else:
                start = index
                while index < len(text):
                    char = text[index]
                    if (flow and char in ",[]{}") or (char == "#" and (index == start or text[index - 1] == " ")):
                        break
                    if char == ":" and (key or index + 1 == len(text) or text[index + 1] == " "):
                        break
                    index += 1
                result = text[start:index].strip()
                if (not result or result[0] in "&*!|>%@`?'\"{}[],"
                        or result in ("---", "...", "<<")
                        or result.startswith(("- ", "? "))):
                    raise core.InventoryError("unsupported pnpm YAML scalar/constructor")
                if not key:
                    if result in ("true", "false"):
                        return result == "true"
                    if result in ("null", "~"):
                        return None
                    if re.fullmatch(r"0|[1-9][0-9]*", result):
                        if len(result) > 20:
                            raise core.InventoryError("pnpm YAML integer exceeds metadata limit")
                        return int(result)
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in result):
                raise core.InventoryError("pnpm YAML contains a surrogate scalar")
            return result

        # Block mapping keys may be quoted and contain colons themselves.
        result = value(depth)
        spaces()
        if index < len(text) and text[index] != "#":
            raise core.InventoryError("unsupported trailing pnpm YAML syntax")
        return result

    def mapping_entry(self, text, depth):
        quote = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if quote == '"' and char == "\\":
                    index += 2
                    continue
                if char == quote:
                    if quote == "'" and text[index:index + 2] == "''":
                        index += 2
                        continue
                    quote = None
            elif char in "'\"" and index == 0:
                quote = char
            elif char == ":" and (index + 1 == len(text) or text[index + 1] == " "):
                key = self.inline(text[:index], depth)
                if not isinstance(key, str) or not key or key == "<<":
                    raise core.InventoryError("invalid pnpm YAML mapping key")
                return key, text[index + 1:].strip()
            index += 1
        raise core.InventoryError("unsupported pnpm YAML mapping entry")

    def block(self, indent, depth):
        self.account(depth)
        is_list = self.lines[self.index][1].startswith("- ")
        result = [] if is_list else {}
        while self.index < len(self.lines):
            current, text = self.lines[self.index]
            if current < indent:
                break
            if current != indent or is_list != text.startswith("- "):
                raise core.InventoryError("inconsistent pnpm YAML indentation/collection")
            self.index += 1
            if is_list:
                result.append(self.inline(text[2:].strip(), depth + 1))
            else:
                key, tail = self.mapping_entry(text, depth + 1)
                if key in result:
                    raise core.InventoryError("duplicate pnpm YAML mapping key")
                if tail and not tail.startswith("#"):
                    result[key] = self.inline(tail, depth + 1)
                elif self.index < len(self.lines) and self.lines[self.index][0] > indent:
                    result[key] = self.block(self.lines[self.index][0], depth + 1)
                else:
                    result[key] = None
        return result

    def parse(self):
        if not self.lines:
            raise core.InventoryError("empty pnpm YAML metadata")
        if self.lines[0][0] != 0:
            raise core.InventoryError("pnpm YAML root must not be indented")
        if len(self.lines) == 1 and self.lines[0][1].startswith("{"):
            result = self.inline(self.lines[0][1])
            self.index = 1
        else:
            result = self.block(0, 0)
        if self.index != len(self.lines) or not isinstance(result, dict):
            raise core.InventoryError("pnpm YAML must be one mapping document")
        return result


def read_yaml(path: Path, limit: int):
    """Bound the bytes before parsing; do not open symlinks or special files."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise core.InventoryError("pnpm metadata must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise core.InventoryError("pnpm metadata changed to a special file")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(raw) > limit or len(raw) != before.st_size
            or identity(before) != identity(opened) or identity(opened) != identity(after)
            or identity(after) != identity(path.lstat())):
        raise core.InventoryError("pnpm metadata changed during capture")
    return _Yaml(raw).parse()


def _mapping(value, label, limit=None):
    if not isinstance(value, dict) or len(value) > (core.MAX_PACKAGES if limit is None else limit):
        raise core.InventoryError(f"pnpm {label} must be a bounded mapping")
    return value


def _identity(key):
    key = core._string(key, "pnpm dependency path")
    # Peer suffixes may nest; do not split at their @ signs or erase context.
    start = key.find("(")
    base = key if start < 0 else key[:start]
    if start >= 0:
        depth = 0
        for char in key[start:]:
            if char == "(":
                depth += 1
                if depth > core.MAX_DEPTH:
                    raise core.InventoryError("pnpm peer context exceeds depth limit")
            elif char == ")":
                depth -= 1
                if depth < 0:
                    raise core.InventoryError("unbalanced pnpm peer context")
            elif depth == 0:
                raise core.InventoryError("invalid pnpm peer context suffix")
        if depth:
            raise core.InventoryError("unbalanced pnpm peer context")
    separator = base.find("@", 1)
    if separator < 1:
        raise core.InventoryError("pnpm dependency ID must include name and resolution")
    name = core._name(base[:separator])
    version = core._string(base[separator + 1:], "pnpm package resolution")
    return base, name, version


def _review(row, note):
    row["notes"] = "; ".join(filter(None, (row["notes"], note)))
    if row["risk_level"] == "low":
        row["risk_level"] = "high"


def inventory(lock, native, manifests):
    if str(lock.get("lockfileVersion")) != "9.0":
        raise core.InventoryError("unsupported pnpm lockfileVersion (expected 9.0)")
    packages = _mapping(lock.get("packages", {}), "packages")
    snapshots = _mapping(lock.get("snapshots", {}), "snapshots")
    importers = _mapping(lock.get("importers"), "importers", core.MAX_WORKSPACES + 1)
    if "." not in importers:
        raise core.InventoryError("pnpm lockfile requires the root importer")
    # Do not silently ignore configuration that can replace package identities.
    for field in ("catalogs", "overrides", "patchedDependencies", "packageExtensionsChecksum"):
        if lock.get(field):
            raise core.InventoryError(f"pnpm {field} requires explicit inventory support")
    rows, locations, metadata, referenced = [], {}, {}, set()
    edges = 0

    def append(row):
        rows.append(row)
        if len(rows) > core.MAX_PACKAGES:
            raise core.InventoryError("pnpm dependency inventory exceeds row limit")

    def account():
        nonlocal edges
        edges += 1
        if edges > core.MAX_DEPENDENCY_EDGES:
            raise core.InventoryError("pnpm dependency edge budget exceeded")

    for key, record in packages.items():
        base, name, version = _identity(key)
        if base != key:
            raise core.InventoryError("pnpm packages metadata must not contain peer suffixes")
        _mapping(record, "package descriptor")
        resolution = _mapping(record.get("resolution", {}), "resolution")
        row = core._row(name, version, native, source="pnpm-lock.yaml#packages",
                        location=key, install=core._bool(record, "hasInstallScript"))
        row.update(location_kind="pnpm-dependency-id", resolution_kind="registry" if PIN.fullmatch(version) else "external")
        if not PIN.fullmatch(version) or any(field != "integrity" for field in resolution):
            _review(row, "Non-registry or customized resolution; target contents were not opened")
        row["integrity"] = resolution.get("integrity")
        if row["integrity"] is not None:
            core._string(row["integrity"], "pnpm integrity")
        else:
            _review(row, "No archive integrity recorded; content remains unverified")
        row["requires_build"] = core._bool(record, "requiresBuild")
        if row["requires_build"]:
            _review(row, "pnpm requiresBuild metadata; build presence/execution needs review")
        for field in ("os", "cpu", "libc", "bundledDependencies"):
            if field in record:
                values = record[field]
                if not isinstance(values, list) or len(values) > core.MAX_PACKAGES:
                    raise core.InventoryError("pnpm platform/bundle metadata must be a bounded array")
                for value in values:
                    core._string(value, "pnpm platform/bundle constraint")
                row[field] = values
        peers = _mapping(record.get("peerDependencies", {}), "peer declarations")
        for name, request in peers.items():
            account()
            core._name(name)
            core._string(request, "pnpm peer request")
        row["peer_dependencies"] = peers
        for field in ("peerDependenciesMeta", "engines"):
            if field in record:
                row[field] = _mapping(record[field], field)
        if "deprecated" in record:
            row["deprecated"] = core._string(record["deprecated"], "pnpm deprecation")
            _review(row, "pnpm records a deprecated package")
        metadata[key] = row
    for key, snapshot in snapshots.items():
        base, name, version = _identity(key)
        _mapping(snapshot, "snapshot")
        if base not in metadata:
            raise core.InventoryError("pnpm snapshot has no package metadata")
        row = dict(metadata[base])
        row.update(package_path=key, location_kind="pnpm-dependency-path", source="pnpm-lock.yaml#snapshots",
                   optional=core._bool(snapshot, "optional"))
        append(row)
        locations[key] = row
        referenced.add(base)
    for key, row in metadata.items():
        if key not in referenced:
            _review(row, "Package metadata has no dependency snapshot; dependency closure is unknown")
            append(row)

    def resolve(installed_as, pin):
        core._name(installed_as)
        pin = core._string(pin, "pnpm locked edge")
        direct = locations.get(pin)
        return direct if direct is not None else locations.get(f"{installed_as}@{pin}")

    def unresolved(installed_as, request, source, section, pin=None):
        name, version = core._alias(installed_as, request)
        # Locked aliases store the real dependency ID, not npm: syntax.
        if pin is not None and not pin.startswith(("link:", "file:", "workspace:")):
            candidate = pin if pin.find("@", 1) > 0 else f"{installed_as}@{pin}"
            _, name, version = _identity(candidate)
        row = core._row(name, version, native, source=source, location=None,
                        unresolved=True, linked=request.startswith(("link:", "file:", "workspace:")), alias=installed_as)
        row.update(dependency_kind=section, declared_in=source)
        _review(row, "pnpm declaration or locked edge needs resolution review")
        append(row)

    for key, snapshot in snapshots.items():
        for section in ("dependencies", "optionalDependencies"):
            for name, pin in _mapping(snapshot.get(section, {}), section).items():
                account()
                selected = resolve(name, pin)
                if selected is None or (name in native and not selected["has_native_addon"]):
                    unresolved(name, pin, f"pnpm-lock.yaml#snapshots/{key}", section, pin)
        transitive_peers = snapshot.get("transitivePeerDependencies", [])
        if not isinstance(transitive_peers, list):
            raise core.InventoryError("pnpm transitive peer names must be an array")
        for name in transitive_peers:
            account()
            core._name(name)
        for name, request in locations[key]["peer_dependencies"].items():
            account()
            pin = snapshot.get("dependencies", {}).get(name)
            if pin is None:
                pin = snapshot.get("optionalDependencies", {}).get(name)
            if pin is None or resolve(name, pin) is None:
                unresolved(name, request, f"pnpm-lock.yaml#packages/{_identity(key)[0]}", "peerDependencies")

    locked_edges = {}
    for directory, importer in importers.items():
        if directory != ".":
            core._path(directory)
        _mapping(importer, "importer")
        by_name = {}
        for section in SECTIONS:
            for name, edge in _mapping(importer.get(section, {}), section).items():
                account()
                core._name(name)
                _mapping(edge, "importer edge")
                request = core._string(edge.get("specifier"), "pnpm importer specifier")
                pin = core._string(edge.get("version"), "pnpm importer pin")
                actual, _ = core._alias(name, request)
                selected = resolve(name, pin)
                by_name[name] = (request, selected)
                if (selected is None or selected["name"] != actual
                        or (name in native and not selected["has_native_addon"])):
                    unresolved(name, request, f"pnpm-lock.yaml#importers/{directory}", section)
        locked_edges[directory] = by_name
    for source, manifest in manifests.items():
        directory = source.rpartition("/")[0] or "."
        for section in core.SECTIONS:
            for name, request in _mapping(manifest.get(section, {}), section).items():
                account()
                name = core._name(name)
                request = core._string(request, "pnpm current declaration")
                actual, _ = core._alias(name, request)
                locked_request, selected = locked_edges.get(directory, {}).get(name, (None, None))
                if (selected is None or selected["name"] != actual or request != locked_request
                        or (name in native and not selected["has_native_addon"])):
                    unresolved(name, request, source, section)
    return sorted(rows, key=lambda row: (row["name"], row["version"] or "",
                                        row["package_path"] or "", row["source"]))


def scan_pnpm_dependencies(project: Path, native: set[str], *, additional_manifests=None):
    if os.path.lexists(project / ".pnpmfile.cjs"):
        raise core.InventoryError("pnpm readPackage hooks require explicit review; no hook was executed")
    lock = read_yaml(project / "pnpm-lock.yaml", core.MAX_LOCK_BYTES)
    if lock is None:
        raise core.InventoryError("selected pnpm lockfile disappeared")
    workspace = read_yaml(project / "pnpm-workspace.yaml", core.MAX_MANIFEST_BYTES) or {}
    for field in ("catalog", "catalogs", "overrides", "patchedDependencies", "packageExtensions"):
        if workspace.get(field):
            raise core.InventoryError(f"pnpm workspace {field} requires explicit inventory support")
    package = core._read(project / "package.json", core.MAX_MANIFEST_BYTES)
    if package and package.get("pnpm"):
        raise core.InventoryError("package.json pnpm configuration requires explicit inventory support")
    manifests = {} if package is None else {"package.json": package}
    manifests.update(core._workspace_manifests(project, {"workspaces": workspace.get("packages", [])}))
    if additional_manifests is not None:
        for source, manifest in _mapping(additional_manifests, "additional manifests", core.MAX_WORKSPACES + 1).items():
            core._path(source)
            if source.split("/")[-1] != "package.json" or not isinstance(manifest, dict):
                raise core.InventoryError("additional manifest must be a project package.json object")
            if source in manifests and manifests[source] != manifest:
                raise core.InventoryError("manifest changed between captured observations")
            manifests[source] = manifest
    if len(manifests) > core.MAX_WORKSPACES + 1:
        raise core.InventoryError("combined pnpm manifest count exceeds inventory limit")
    return inventory(lock, native, manifests)
