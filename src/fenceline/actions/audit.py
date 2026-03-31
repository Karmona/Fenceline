"""Audit GitHub Actions workflows for supply chain risks.

The TeamPCP campaign (March 2026) showed that action tags can be
force-pushed.  SHA pinning is the only reliable defense.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from dataclasses import dataclass, field

import yaml


# 40-char lowercase hex SHA
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Matches a `uses:` value — org/repo@ref or just action@ref
_USES_RE = re.compile(r"^\s*uses:\s*['\"]?(.+?)(?:#.+)?['\"]?\s*$")


@dataclass
class Finding:
    workflow: str
    action: str
    ref: str
    level: str  # PASS, WARNING, CRITICAL, SKIP
    reason: str


def _classify(action_str: str) -> Finding | None:
    """Classify a single `uses:` value and return a Finding (or None to skip)."""
    # Docker actions
    if action_str.startswith("docker://"):
        return Finding("", action_str, "", "SKIP", "Docker action")

    # Local actions
    if action_str.startswith("./") or action_str.startswith("../"):
        return Finding("", action_str, "", "SKIP", "Local action")

    # Split on @
    if "@" not in action_str:
        return Finding("", action_str, "", "WARNING", "No ref specified")

    action, ref = action_str.rsplit("@", 1)

    if _SHA_RE.match(ref):
        return Finding("", action, ref, "PASS", "Pinned to SHA")

    if ref in ("main", "master"):
        return Finding(
            "", action, ref, "CRITICAL",
            f"Pinned to @{ref} — always pulls latest, extremely dangerous"
        )

    # Anything else is a tag (v4, v1.2.3, etc.)
    return Finding(
        "", action, ref, "WARNING",
        f"Pinned to tag @{ref} — tags can be force-pushed (see TeamPCP campaign)"
    )


def _extract_uses(step: dict) -> str | None:
    """Pull the uses string from a workflow step dict."""
    return step.get("uses")


def _scan_workflow(path: str) -> list[Finding]:
    """Parse one workflow YAML and return findings for every `uses:` line."""
    findings: list[Finding] = []
    with open(path) as fh:
        try:
            doc = yaml.safe_load(fh)
        except yaml.YAMLError:
            return findings

    if not isinstance(doc, dict):
        return findings

    jobs = doc.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    for _job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = _extract_uses(step)
            if uses is None:
                continue
            finding = _classify(uses)
            if finding is not None:
                finding.workflow = os.path.basename(path)
                findings.append(finding)

    return findings


# -- Formatting ---------------------------------------------------------------

_COLORS = {
    "PASS": "\033[32m",      # green
    "WARNING": "\033[33m",   # yellow
    "CRITICAL": "\033[31m",  # red
    "SKIP": "\033[90m",      # grey
    "RESET": "\033[0m",
}


def _fmt(level: str, no_color: bool) -> tuple[str, str]:
    if no_color:
        return "", ""
    return _COLORS.get(level, ""), _COLORS["RESET"]


def _print_report(findings: list[Finding], *, verbose: bool, no_color: bool) -> None:
    for f in findings:
        if f.level == "SKIP" and not verbose:
            continue
        pre, post = _fmt(f.level, no_color)
        tag = f"[{f.level:>8s}]"
        action_display = f"{f.action}@{f.ref}" if f.ref else f.action
        print(f"  {pre}{tag}{post}  {f.workflow}: {action_display}")
        if verbose or f.level in ("WARNING", "CRITICAL"):
            print(f"           {f.reason}")


# -- Entry point --------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    """Scan GitHub Actions workflows and report supply chain risks."""
    search_path = getattr(args, "path", None) or "."
    workflow_dir = os.path.join(search_path, ".github", "workflows")

    patterns = [
        os.path.join(workflow_dir, "*.yml"),
        os.path.join(workflow_dir, "*.yaml"),
    ]
    files = sorted(set(f for p in patterns for f in glob.glob(p)))

    if not files:
        print(f"No workflow files found in {workflow_dir}")
        return 0

    no_color = getattr(args, "no_color", False)
    verbose = getattr(args, "verbose", False)

    all_findings: list[Finding] = []
    for path in files:
        all_findings.extend(_scan_workflow(path))

    if not all_findings:
        print("No actions found in workflows.")
        return 0

    _print_report(all_findings, verbose=verbose, no_color=no_color)

    # Summary
    counts = {}
    for f in all_findings:
        counts[f.level] = counts.get(f.level, 0) + 1

    print()
    parts = []
    for level in ("CRITICAL", "WARNING", "PASS", "SKIP"):
        if level in counts:
            pre, post = _fmt(level, no_color)
            parts.append(f"{pre}{counts[level]} {level}{post}")
    print("  " + " | ".join(parts))

    has_critical = any(f.level == "CRITICAL" for f in all_findings)
    return 1 if has_critical else 0
