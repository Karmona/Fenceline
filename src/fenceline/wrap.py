"""Shell wrapper/alias setup for transparent sandboxed installs.

Makes Fenceline invisible in the developer workflow:
  fenceline wrap --enable    # npm/npx now route through sandbox
  fenceline wrap --disable   # restore originals
  fenceline wrap --status    # show current state

After enabling, running `npm install express` automatically goes through
the Docker sandbox. No need to remember `fenceline install --sandbox`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The shell wrapper script that intercepts npm/npx/yarn/pnpm
_WRAPPER_SCRIPT = '''\
#!/usr/bin/env bash
# Fenceline dependency firewall wrapper
# Installed by: fenceline wrap --enable
# Remove with: fenceline wrap --disable
#
# This intercepts package install commands and routes them through
# the Fenceline Docker sandbox. Non-install commands pass through
# to the real tool unchanged.

REAL_CMD="{real_path}"
FENCELINE_CMD="{fenceline_path}"

# Check if this is an install command
# Match: install, add, i, ci (npm ci)
# Only match as the FIRST non-flag argument to avoid false positives like "npm run add"
IS_INSTALL=false
FOUND_VERB=false
for arg in "$@"; do
    case "$arg" in
        -*) continue;;  # skip flags
        install|add|i|ci)
            if [ "$FOUND_VERB" = false ]; then
                IS_INSTALL=true
            fi
            break;;
        *)
            FOUND_VERB=true
            break;;
    esac
done

if [ "$IS_INSTALL" = true ]; then
    if command -v docker >/dev/null 2>&1; then
        # Route through sandbox
        exec "$FENCELINE_CMD" install --sandbox "$(basename "$0")" "$@"
    else
        # FAIL CLOSED: Docker not available, block the install
        echo "[fenceline] BLOCKED: Docker is not running. Cannot sandbox this install." >&2
        echo "[fenceline] Start Docker, or run the real command directly: $REAL_CMD $*" >&2
        exit 1
    fi
else
    # Non-install commands pass through unchanged
    exec "$REAL_CMD" "$@"
fi
'''

_WRAPPER_DIR = Path.home() / ".fenceline" / "bin"
_TOOLS = ["npm", "npx", "yarn", "pnpm", "pip", "pip3"]


def _find_real_tool(name: str) -> str | None:
    """Find the real tool binary, skipping our wrapper."""
    import shutil
    # Check common locations, skipping our wrapper dir
    for path_dir in os.environ.get("PATH", "").split(":"):
        if str(_WRAPPER_DIR) in path_dir:
            continue
        candidate = Path(path_dir) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def _find_fenceline() -> str:
    """Find the fenceline CLI binary."""
    import shutil
    return shutil.which("fenceline") or "fenceline"


def run(args) -> int:
    """Handle fenceline wrap subcommand."""
    enable = getattr(args, 'enable', False)
    disable = getattr(args, 'disable', False)
    status = getattr(args, 'status', False)

    if not (enable or disable or status):
        print("Usage: fenceline wrap --enable | --disable | --status")
        return 1

    if status:
        return _show_status()
    elif enable:
        return _enable_wrappers()
    elif disable:
        return _disable_wrappers()
    return 0


def _show_status() -> int:
    """Show which tools are wrapped."""
    if not _WRAPPER_DIR.exists():
        print("[fenceline] No wrappers installed.")
        print(f"[fenceline] Run 'fenceline wrap --enable' to intercept npm/yarn/pnpm installs.")
        return 0

    wrapped = []
    for tool in _TOOLS:
        wrapper = _WRAPPER_DIR / tool
        if wrapper.exists():
            wrapped.append(tool)

    if wrapped:
        print(f"[fenceline] Wrapped: {', '.join(wrapped)}")
        print(f"[fenceline] Install commands for these tools route through the Docker sandbox.")
        if str(_WRAPPER_DIR) not in os.environ.get("PATH", ""):
            print(f"[fenceline] WARNING: {_WRAPPER_DIR} is not in your PATH.")
            print(f"[fenceline] Add this to your shell profile:")
            print(f'           export PATH="{_WRAPPER_DIR}:$PATH"')
    else:
        print("[fenceline] No wrappers installed.")

    return 0


def _enable_wrappers() -> int:
    """Install wrapper scripts for npm/npx/yarn/pnpm."""
    _WRAPPER_DIR.mkdir(parents=True, exist_ok=True)
    fenceline_path = _find_fenceline()

    installed = []
    for tool in _TOOLS:
        real_path = _find_real_tool(tool)
        if real_path is None:
            continue

        wrapper_path = _WRAPPER_DIR / tool
        script = _WRAPPER_SCRIPT.format(
            real_path=real_path,
            fenceline_path=fenceline_path,
        )
        wrapper_path.write_text(script)
        wrapper_path.chmod(0o755)
        installed.append(tool)

    if not installed:
        print("[fenceline] No package managers found.", file=sys.stderr)
        return 1

    if "pip" in installed or "pip3" in installed:
        print("[fenceline] Note: pip/pip3 wrappers are installed. They work best inside a virtualenv.")

    print(f"[fenceline] Wrappers installed for: {', '.join(installed)}")
    print(f"[fenceline] Location: {_WRAPPER_DIR}")

    if str(_WRAPPER_DIR) not in os.environ.get("PATH", ""):
        print(f"\n[fenceline] Add this to your ~/.zshrc or ~/.bashrc:")
        print(f'  export PATH="{_WRAPPER_DIR}:$PATH"')
        print(f"\n[fenceline] Then restart your shell or run:")
        print(f'  source ~/.zshrc')

    print(f"\n[fenceline] Now `npm install <pkg>` automatically goes through the Docker sandbox.")
    print(f"[fenceline] Non-install commands (npm test, npm run, etc.) pass through unchanged.")
    return 0


def _disable_wrappers() -> int:
    """Remove wrapper scripts."""
    if not _WRAPPER_DIR.exists():
        print("[fenceline] No wrappers to remove.")
        return 0

    removed = []
    for tool in _TOOLS:
        wrapper = _WRAPPER_DIR / tool
        if wrapper.exists():
            wrapper.unlink()
            removed.append(tool)

    if removed:
        print(f"[fenceline] Removed wrappers for: {', '.join(removed)}")
        print(f"[fenceline] npm/yarn/pnpm now use the original binaries.")
    else:
        print("[fenceline] No wrappers found to remove.")

    return 0
