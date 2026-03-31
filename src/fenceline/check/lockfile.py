"""Parse lockfiles (package-lock.json, Pipfile.lock, requirements.txt) and compute diffs."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PackageChange:
    """A single package that was added, updated, or removed."""

    name: str
    old_version: str | None
    new_version: str | None
    resolved_url: str | None
    integrity: str | None
    has_install_script: bool
    change_type: str  # "added" | "updated" | "removed"


def parse_lockfile(path: Path) -> dict:
    """Load a package-lock.json and return a normalised package map.

    Supports lockfileVersion 2 and 3.  Returns a dict keyed by
    package name (with ``node_modules/`` prefix stripped) whose values
    are dicts with ``version``, ``resolved``, ``integrity``, and
    ``hasInstallScript`` fields.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    lockfile_version = raw.get("lockfileVersion", 1)
    if lockfile_version < 2:
        raise ValueError(
            f"Unsupported lockfileVersion {lockfile_version}. "
            "Only v2 and v3 are supported."
        )

    packages: dict[str, dict] = {}
    for key, meta in raw.get("packages", {}).items():
        # Skip the root entry (empty string key).
        if not key:
            continue

        # Strip leading node_modules/ (possibly nested).
        name = _strip_node_modules(key)
        if not name:
            continue

        packages[name] = {
            "version": meta.get("version"),
            "resolved": meta.get("resolved"),
            "integrity": meta.get("integrity"),
            "hasInstallScript": meta.get("hasInstallScript", False),
        }

    return packages


def parse_pipfile_lock(path: Path) -> dict:
    """Load a Pipfile.lock and return a normalised package map.

    Pipfile.lock is JSON with ``default`` and ``develop`` sections, each
    mapping package names to ``{version, hashes, ...}``.  Returns a dict
    keyed by package name whose values have ``version``, ``resolved``,
    ``integrity``, and ``hasInstallScript`` fields (the latter two are
    ``None``/``False`` for pip packages).
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    packages: dict[str, dict] = {}
    for section in ("default", "develop"):
        for name, meta in raw.get(section, {}).items():
            version = meta.get("version", "")
            # Pipfile.lock versions are prefixed with "==" — strip it.
            if version.startswith("=="):
                version = version[2:]
            packages[name] = {
                "version": version,
                "resolved": None,
                "integrity": None,
                "hasInstallScript": False,
            }

    return packages


def parse_requirements_txt(path: Path) -> list[dict]:
    """Parse a requirements.txt file and return a list of package dicts.

    Each line is expected to be ``package==version``.  Lines starting
    with ``#``, ``-``, or blank lines are skipped.  Returns a list of
    dicts with ``name`` and ``version`` keys.
    """
    packages: list[dict] = []
    text = path.read_text(encoding="utf-8")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;#]+)", line)
        if match:
            packages.append({"name": match.group(1).lower(), "version": match.group(2)})

    return packages


def parse_requirements_txt_as_map(path: Path) -> dict:
    """Parse requirements.txt into a normalised package map (same shape as lockfile parsers)."""
    packages: dict[str, dict] = {}
    for pkg in parse_requirements_txt(path):
        packages[pkg["name"]] = {
            "version": pkg["version"],
            "resolved": None,
            "integrity": None,
            "hasInstallScript": False,
        }
    return packages


# Ordered by preference.
_LOCKFILE_CANDIDATES = [
    ("npm", "package-lock.json"),
    ("pipfile", "Pipfile.lock"),
    ("requirements", "requirements.txt"),
    ("yarn", "yarn.lock"),
    ("pnpm", "pnpm-lock.yaml"),
]


def detect_lockfile(directory: Path) -> tuple[str, Path] | None:
    """Auto-detect which lockfile exists in *directory*.

    Checks in order: package-lock.json, Pipfile.lock, requirements.txt,
    yarn.lock, pnpm-lock.yaml.  Returns ``(type, path)`` or ``None``.
    """
    for lockfile_type, filename in _LOCKFILE_CANDIDATES:
        candidate = directory / filename
        if candidate.is_file():
            return (lockfile_type, candidate)
    return None


def _strip_node_modules(key: str) -> str:
    """Strip the ``node_modules/`` prefix from a packages key.

    Handles nested paths like ``node_modules/express/node_modules/debug``
    by returning the last ``node_modules/<name>`` segment — but keeps
    scoped packages intact (``@scope/name``).
    """
    parts = key.split("node_modules/")
    # Take the last non-empty segment.
    for part in reversed(parts):
        stripped = part.rstrip("/")
        if stripped:
            return stripped
    return ""


def get_base_lockfile(
    lockfile_path: Path,
    base_ref: str,
    lockfile_type: str = "npm",
) -> dict | None:
    """Retrieve the lockfile content from a git ref.

    Returns the parsed package map, or ``None`` if the file does not
    exist at *base_ref*.  *lockfile_type* should be ``"npm"``,
    ``"pipfile"``, or ``"requirements"``.
    """
    try:
        # Determine the repo-relative path.
        repo_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            cwd=lockfile_path.parent,
        ).stdout.strip()

        relative = lockfile_path.resolve().relative_to(Path(repo_root).resolve())
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{relative}"],
            capture_output=True,
            text=True,
            cwd=repo_root,
        )

        if result.returncode != 0:
            return None

        content = result.stdout
    except (subprocess.CalledProcessError, ValueError):
        return None

    return _parse_base_content(content, lockfile_type)


def _parse_base_content(content: str, lockfile_type: str) -> dict | None:
    """Parse raw lockfile content retrieved from git."""
    if lockfile_type == "pipfile":
        try:
            raw = json.loads(content)
        except json.JSONDecodeError:
            return None
        packages: dict[str, dict] = {}
        for section in ("default", "develop"):
            for name, meta in raw.get(section, {}).items():
                version = meta.get("version", "")
                if version.startswith("=="):
                    version = version[2:]
                packages[name] = {
                    "version": version,
                    "resolved": None,
                    "integrity": None,
                    "hasInstallScript": False,
                }
        return packages

    if lockfile_type == "requirements":
        packages = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;#]+)", line)
            if match:
                packages[match.group(1).lower()] = {
                    "version": match.group(2),
                    "resolved": None,
                    "integrity": None,
                    "hasInstallScript": False,
                }
        return packages

    # Default: npm
    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        return None

    lockfile_version = raw.get("lockfileVersion", 1)
    if lockfile_version < 2:
        return None

    packages = {}
    for key, meta in raw.get("packages", {}).items():
        if not key:
            continue
        name = _strip_node_modules(key)
        if not name:
            continue
        packages[name] = {
            "version": meta.get("version"),
            "resolved": meta.get("resolved"),
            "integrity": meta.get("integrity"),
            "hasInstallScript": meta.get("hasInstallScript", False),
        }

    return packages


def diff_lockfiles(base: dict, head: dict) -> list[PackageChange]:
    """Compute the list of package changes between *base* and *head*.

    Both arguments are normalised package maps as returned by
    :func:`parse_lockfile`.
    """
    changes: list[PackageChange] = []

    all_names = set(base) | set(head)

    for name in sorted(all_names):
        in_base = name in base
        in_head = name in head

        if in_head and not in_base:
            pkg = head[name]
            changes.append(
                PackageChange(
                    name=name,
                    old_version=None,
                    new_version=pkg["version"],
                    resolved_url=pkg.get("resolved"),
                    integrity=pkg.get("integrity"),
                    has_install_script=pkg.get("hasInstallScript", False),
                    change_type="added",
                )
            )
        elif in_base and not in_head:
            pkg = base[name]
            changes.append(
                PackageChange(
                    name=name,
                    old_version=pkg["version"],
                    new_version=None,
                    resolved_url=None,
                    integrity=None,
                    has_install_script=False,
                    change_type="removed",
                )
            )
        else:
            base_pkg = base[name]
            head_pkg = head[name]
            if base_pkg["version"] != head_pkg["version"]:
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=base_pkg["version"],
                        new_version=head_pkg["version"],
                        resolved_url=head_pkg.get("resolved"),
                        integrity=head_pkg.get("integrity"),
                        has_install_script=head_pkg.get("hasInstallScript", False),
                        change_type="updated",
                    )
                )

    return changes
