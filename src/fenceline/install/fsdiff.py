"""Filesystem diffing for sandbox installs.

Snapshots the container filesystem before and after install to detect
suspicious changes: dropped binaries, unexpected executables, files
in locations packages should never touch.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class FileEntry:
    """A file observed in the container filesystem."""

    path: str
    permissions: str  # e.g. "0755", "0644"
    size: int


@dataclass
class FsAlert:
    """An alert raised by filesystem diffing."""

    path: str
    reason: str
    severity: str  # "warning" | "critical"


# Directories where new files are expected during npm/pip install
_EXPECTED_DIRS = {
    "npm": {"/app/node_modules", "/app/package-lock.json", "/app/package.json"},
    "yarn": {"/app/node_modules", "/app/yarn.lock", "/app/package.json"},
    "pnpm": {"/app/node_modules", "/app/pnpm-lock.yaml", "/app/package.json"},
    "pip": {"/usr/local/lib/python", "/usr/local/bin"},
    "pip3": {"/usr/local/lib/python", "/usr/local/bin"},
}

# Locations that should never have new files from a package install
_SUSPICIOUS_DIRS = {"/etc", "/root", "/home", "/var/spool/cron", "/usr/lib/systemd"}

# File extensions that suggest dropped binaries
_SUSPICIOUS_EXTENSIONS = {".so", ".dylib", ".dll", ".exe", ".elf", ".sh", ".bash"}


def snapshot_container(docker_bin: str, container_id: str, root: str = "/app") -> Dict[str, FileEntry]:
    """Take a filesystem snapshot of the container.

    Uses `find` with stat-like output to get path, permissions, and size.
    Returns a dict mapping path -> FileEntry.
    """
    try:
        result = subprocess.run(
            [docker_bin, "exec", container_id, "find", root,
             "-type", "f", "-printf", "%p\\t%m\\t%s\\n"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    return parse_find_output(result.stdout)


def parse_find_output(output: str) -> Dict[str, FileEntry]:
    """Parse output from find -printf '%p\\t%m\\t%s\\n'."""
    files: Dict[str, FileEntry] = {}
    for line in output.strip().splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        path, perms, size_str = parts
        try:
            size = int(size_str)
        except ValueError:
            size = 0
        files[path] = FileEntry(path=path, permissions=perms, size=size)
    return files


def diff_snapshots(
    before: Dict[str, FileEntry],
    after: Dict[str, FileEntry],
) -> Tuple[List[FileEntry], List[FileEntry], List[FileEntry]]:
    """Compare two filesystem snapshots.

    Returns (added, removed, modified) file lists.
    """
    before_paths = set(before.keys())
    after_paths = set(after.keys())

    added = [after[p] for p in sorted(after_paths - before_paths)]
    removed = [before[p] for p in sorted(before_paths - after_paths)]

    modified = []
    for p in sorted(before_paths & after_paths):
        b, a = before[p], after[p]
        if b.permissions != a.permissions or b.size != a.size:
            modified.append(a)

    return added, removed, modified


def check_suspicious_files(
    added: List[FileEntry],
    modified: List[FileEntry],
    tool_id: str,
) -> List[FsAlert]:
    """Check added/modified files for suspicious patterns.

    Returns a list of filesystem alerts.
    """
    alerts: List[FsAlert] = []
    expected_prefixes = _EXPECTED_DIRS.get(tool_id, set())

    for entry in added:
        # Check if file is in a suspicious location
        for suspicious_dir in _SUSPICIOUS_DIRS:
            if entry.path.startswith(suspicious_dir):
                alerts.append(FsAlert(
                    path=entry.path,
                    reason=f"New file in sensitive directory {suspicious_dir}",
                    severity="critical",
                ))
                break

        # Check if file is outside expected install directories
        in_expected = any(entry.path.startswith(prefix) for prefix in expected_prefixes)
        if not in_expected and not _is_harmless_path(entry.path):
            # Executable outside expected dirs is suspicious
            if _is_executable(entry.permissions):
                alerts.append(FsAlert(
                    path=entry.path,
                    reason="New executable file outside expected install directories",
                    severity="critical",
                ))
            # Non-executable in unexpected location is a warning
            elif entry.size > 0:
                for ext in _SUSPICIOUS_EXTENSIONS:
                    if entry.path.endswith(ext):
                        alerts.append(FsAlert(
                            path=entry.path,
                            reason=f"Suspicious file type ({ext}) outside expected directories",
                            severity="warning",
                        ))
                        break

    # Check for permission escalation on modified files
    for entry in modified:
        if _is_executable(entry.permissions):
            in_expected = any(entry.path.startswith(prefix) for prefix in expected_prefixes)
            if not in_expected:
                alerts.append(FsAlert(
                    path=entry.path,
                    reason="File made executable outside expected directories",
                    severity="warning",
                ))

    return alerts


def _is_executable(permissions: str) -> bool:
    """Check if file permissions include any execute bit."""
    try:
        mode = int(permissions, 8)
        return bool(mode & 0o111)
    except ValueError:
        return False


def _is_harmless_path(path: str) -> bool:
    """Paths that are always fine to create (temp files, caches, logs)."""
    harmless = {"/app/package-lock.json", "/app/yarn.lock", "/app/pnpm-lock.yaml",
                "/app/package.json"}
    if path in harmless:
        return True
    # npm/yarn cache dirs
    if "/app/.cache/" in path or "/app/.npm/" in path:
        return True
    if path.startswith("/tmp/"):
        # /tmp is OK for temp files during build, but not for binaries
        return not _is_executable("755")  # We flag /tmp executables elsewhere
    return False
