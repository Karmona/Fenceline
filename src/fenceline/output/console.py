"""Terminal output helpers for Fenceline.

Matches the color/output style from tools/quick-check.sh.
Respects NO_COLOR env var and --no-color flag.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

# ANSI color codes -- disabled when NO_COLOR is set or --no-color is passed
_RED = "\033[0;31m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[0;33m"
_BOLD = "\033[1m"
_NC = "\033[0m"

_no_color_override: bool = False


def set_no_color(value: bool) -> None:
    """Set the global no-color override (from --no-color flag)."""
    global _no_color_override
    _no_color_override = value


def _use_color() -> bool:
    """Determine if color output should be used."""
    if _no_color_override:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap text in an ANSI color code if color is enabled."""
    if _use_color():
        return f"{code}{text}{_NC}"
    return text


def pass_msg(text: str) -> None:
    """Print a PASS message."""
    label = _c(_GREEN, "PASS")
    print(f"  {label}  {text}")


def fail_msg(text: str) -> None:
    """Print a FAIL message."""
    label = _c(_RED, "FAIL")
    print(f"  {label}  {text}")


def warn_msg(text: str) -> None:
    """Print a WARN message."""
    label = _c(_YELLOW, "WARN")
    print(f"  {label}  {text}")


def info_msg(text: str) -> None:
    """Print an INFO message."""
    label = _c(_BOLD, "INFO")
    print(f"  {label}  {text}")


def skip_msg(text: str) -> None:
    """Print a SKIP message."""
    label = _c(_BOLD, "SKIP")
    print(f"  {label}  {text}")


def print_header(text: str) -> None:
    """Print a bold section header."""
    print(_c(_BOLD, text))


def print_separator() -> None:
    """Print a visual separator line."""
    print("============================================")


def print_risk_report(results: List[Dict[str, Any]], verbose: bool = False) -> None:
    """Print a table-formatted risk report from fenceline check results.

    Each result dict is expected to have:
        status: "pass" | "fail" | "warn" | "skip" | "info"
        message: str
        detail: str (optional, shown in verbose mode)
    """
    for r in results:
        status = r.get("status", "info")
        message = r.get("message", "")
        detail = r.get("detail", "")

        if status == "pass":
            pass_msg(message)
        elif status == "fail":
            fail_msg(message)
        elif status == "warn":
            warn_msg(message)
        elif status == "skip":
            skip_msg(message)
        else:
            info_msg(message)

        if verbose and detail:
            for line in detail.splitlines():
                print(f"        {line}")


def print_install_alert(alert: Dict[str, Any]) -> None:
    """Print a real-time alert during install monitoring.

    Alert dict is expected to have:
        level: "pass" | "fail" | "warn" | "info"
        message: str
        domain: str (optional)
        ip: str (optional)
    """
    level = alert.get("level", "info")
    message = alert.get("message", "")
    domain = alert.get("domain", "")
    ip = alert.get("ip", "")

    suffix = ""
    if domain:
        suffix += f" [{domain}]"
    if ip:
        suffix += f" ({ip})"

    full_message = f"{message}{suffix}"

    if level == "pass":
        pass_msg(full_message)
    elif level == "fail":
        fail_msg(full_message)
    elif level == "warn":
        warn_msg(full_message)
    else:
        info_msg(full_message)


def print_summary(passed: int, total: int) -> None:
    """Print a one-line summary with score and posture rating."""
    print_separator()
    print_header(f"  RESULTS: {passed} / {total} checks passed")
    print_separator()

    if total > 0:
        pct = passed * 100 // total
    else:
        pct = 0

    if pct >= 80:
        print(f"  {_c(_GREEN, 'Good posture.')} Keep your lockfile reviewed and dependencies updated.")
    elif pct >= 50:
        print(f"  {_c(_YELLOW, 'Room for improvement.')} Review the FAIL items above.")
    else:
        print(f"  {_c(_RED, 'Significant gaps.')} Address the FAIL items above -- start with the easiest ones.")

    print()
