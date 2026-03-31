"""Git hook installer for Fenceline.

Usage: fenceline init [--force]
Installs pre-commit and post-merge hooks that run fenceline check
when lockfiles change.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from typing import List

MARKER = "# fenceline-hook"

PRE_COMMIT_HOOK = f"""\
{MARKER}
# Fenceline supply chain check — runs when lockfiles are staged
LOCKFILES="package-lock.json yarn.lock pnpm-lock.yaml Cargo.lock Gemfile.lock poetry.lock requirements.txt"
STAGED_LOCKFILE=""
for f in $LOCKFILES; do
    if git diff --cached --name-only | grep -q "$f"; then
        STAGED_LOCKFILE="$f"
        break
    fi
done
if [ -n "$STAGED_LOCKFILE" ]; then
    echo "[fenceline] Lockfile changed ($STAGED_LOCKFILE) — running supply chain check..."
    fenceline check --base-ref HEAD
    if [ $? -ne 0 ]; then
        echo "[fenceline] Supply chain check raised issues. Commit anyway with --no-verify."
    fi
fi
{MARKER}-end
"""

POST_MERGE_HOOK = f"""\
{MARKER}
# Fenceline supply chain check — runs after merge if lockfiles changed
LOCKFILES="package-lock.json yarn.lock pnpm-lock.yaml Cargo.lock Gemfile.lock poetry.lock requirements.txt"
CHANGED_LOCKFILE=""
for f in $LOCKFILES; do
    if git diff --name-only HEAD@{{1}} HEAD | grep -q "$f"; then
        CHANGED_LOCKFILE="$f"
        break
    fi
done
if [ -n "$CHANGED_LOCKFILE" ]; then
    echo "[fenceline] Lockfile changed ($CHANGED_LOCKFILE) — running supply chain check..."
    fenceline check --base-ref "HEAD@{{1}}"
fi
{MARKER}-end
"""


def run(args) -> int:
    """Install git hooks for Fenceline.

    Args:
        args: argparse.Namespace or list. Supports --force to overwrite existing hooks.

    Returns:
        0 on success, 1 on error.
    """
    force = getattr(args, 'force', False) if hasattr(args, 'force') else "--force" in args

    # Find .git directory
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            check=True,
        )
        git_dir = result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: not a git repository.", file=sys.stderr)
        return 1

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    # Install each hook
    hooks = {
        "pre-commit": PRE_COMMIT_HOOK,
        "post-merge": POST_MERGE_HOOK,
    }

    for hook_name, hook_content in hooks.items():
        hook_path = os.path.join(hooks_dir, hook_name)
        _install_hook(hook_path, hook_name, hook_content, force)

    print("[fenceline] Git hooks installed successfully.")
    return 0


def _install_hook(
    hook_path: str, hook_name: str, hook_content: str, force: bool
) -> None:
    """Install or update a single git hook file."""
    if os.path.exists(hook_path):
        existing = _read_file(hook_path)

        if MARKER in existing:
            # Replace existing fenceline section
            updated = _replace_section(existing, hook_content)
            _write_file(hook_path, updated)
            print(f"  Updated {hook_name} hook (replaced fenceline section).")
        elif force:
            # Append to existing hook
            updated = existing.rstrip("\n") + "\n\n" + hook_content
            _write_file(hook_path, updated)
            print(f"  Updated {hook_name} hook (appended fenceline section).")
        else:
            print(
                f"  Warning: {hook_name} hook exists without fenceline marker. "
                f"Use --force to append.",
                file=sys.stderr,
            )
            return
    else:
        # Create new hook file
        content = "#!/usr/bin/env bash\nset -e\n\n" + hook_content
        _write_file(hook_path, content)
        print(f"  Created {hook_name} hook.")

    # Make executable
    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _replace_section(existing: str, new_section: str) -> str:
    """Replace the fenceline-marked section in an existing hook."""
    marker_start = MARKER
    marker_end = f"{MARKER}-end"

    start_idx = existing.find(marker_start)
    end_idx = existing.find(marker_end)

    if start_idx == -1 or end_idx == -1:
        return existing

    # Include the marker_end line itself
    end_of_marker = existing.find("\n", end_idx)
    if end_of_marker == -1:
        end_of_marker = len(existing)
    else:
        end_of_marker += 1  # Include the newline

    return existing[:start_idx] + new_section + existing[end_of_marker:]


def _read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()


def _write_file(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)
