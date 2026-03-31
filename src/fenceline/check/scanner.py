"""Orchestrator: tie lockfile diffing, registry queries, and scoring together."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .lockfile import parse_lockfile, get_base_lockfile, diff_lockfiles
from .registry import get_package_info, get_package_age, get_maintainer_change
from .provenance import check_provenance
from .capabilities import check_capabilities
from .scoring import compute_risk, RiskReport


def run(args) -> int:
    """Run the fenceline check pipeline.

    *args* is an argparse-style namespace with at least:
        - ``lockfile``: optional explicit path (str | None)
        - ``base_ref``: git ref to compare against (default ``"HEAD"``)
        - ``format``: output format (``"console"`` | ``"json"`` | ``"markdown"``)

    Returns 0 if all packages are LOW/MEDIUM, 1 if any HIGH/CRITICAL
    found, and 2 on error.
    """
    lockfile_path = _find_lockfile(getattr(args, "lockfile", None))
    if lockfile_path is None:
        print("Error: no package-lock.json found.", file=sys.stderr)
        return 2

    base_ref = getattr(args, "base_ref", "HEAD")
    fmt = getattr(args, "format", "console")

    # --- Parse head lockfile ---
    try:
        head = parse_lockfile(lockfile_path)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error parsing lockfile: {exc}", file=sys.stderr)
        return 2

    # --- Get base lockfile from git ---
    base = get_base_lockfile(lockfile_path, base_ref)
    if base is None:
        # First commit or no git — treat everything as new.
        base = {}

    # --- Compute diff ---
    changes = diff_lockfiles(base, head)
    if not changes:
        print("No dependency changes detected.")
        return 0

    print(f"Checking {len(changes)} package(s)...\n")

    # --- Analyse each change ---
    reports: list[RiskReport] = []
    for change in changes:
        pkg_name = change.name
        version = change.new_version or change.old_version or ""

        info = get_package_info(pkg_name)
        if info is None:
            # Unknown package — score with minimal data.
            age = None
            maint = {"changed": False, "added": [], "removed": []}
            prov = {"has_provenance": False, "has_signatures": False, "attestation_count": 0}
            caps: list[str] = []
        else:
            age = get_package_age(info, version) if version else None
            maint = get_maintainer_change(info, change.old_version, version)
            prov = check_provenance(pkg_name, version) if version else {
                "has_provenance": False,
                "has_signatures": False,
                "attestation_count": 0,
            }
            caps = check_capabilities(info, version)

        report = compute_risk(change, age, maint, prov, caps)
        reports.append(report)

    # --- Sort by risk (highest first) ---
    reports.sort(key=lambda r: r.score, reverse=True)

    # --- Output ---
    if fmt == "json":
        _output_json(reports)
    elif fmt == "markdown":
        _output_markdown(reports)
    else:
        _output_console(reports)

    # --- Exit code ---
    max_level = max((r.score for r in reports), default=0)
    if max_level > 35:  # HIGH or CRITICAL
        return 1
    return 0


def _find_lockfile(explicit: str | None) -> Path | None:
    """Locate the lockfile to analyse."""
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else None

    candidate = Path.cwd() / "package-lock.json"
    if candidate.is_file():
        return candidate

    return None


def _output_console(reports: list[RiskReport]) -> None:
    for r in reports:
        icon = {"LOW": ".", "MEDIUM": "~", "HIGH": "!", "CRITICAL": "X"}
        marker = icon.get(r.level, "?")
        ver = f"{r.old_version or '(new)'} -> {r.new_version or '(removed)'}"
        print(f"[{marker}] {r.level:8s} ({r.score:3d}) {r.name}  {ver}")
        for s in r.signals:
            print(f"         +{s['points']:2d}  {s['signal']}: {s['detail']}")
        print()


def _output_json(reports: list[RiskReport]) -> None:
    data = []
    for r in reports:
        data.append({
            "name": r.name,
            "old_version": r.old_version,
            "new_version": r.new_version,
            "change_type": r.change_type,
            "score": r.score,
            "level": r.level,
            "signals": r.signals,
        })
    print(json.dumps(data, indent=2))


def _output_markdown(reports: list[RiskReport]) -> None:
    print("| Package | Change | Score | Level | Signals |")
    print("|---------|--------|-------|-------|---------|")
    for r in reports:
        ver = f"{r.old_version or 'new'} -> {r.new_version or 'removed'}"
        sigs = ", ".join(s["signal"] for s in r.signals) or "none"
        print(f"| {r.name} | {ver} | {r.score} | {r.level} | {sigs} |")
