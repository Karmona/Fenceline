"""Fenceline CLI entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__


def _cmd_check(args: argparse.Namespace) -> int:
    from .check.scanner import run
    return run(args)


def _cmd_install(args: argparse.Namespace) -> int:
    from .install.wrapper import run
    return run(args)


def _cmd_init(args: argparse.Namespace) -> int:
    from .init.hooks import run
    return run(args)


def _cmd_audit_actions(args: argparse.Namespace) -> int:
    from .actions.audit import run
    return run(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fenceline",
        description="Supply chain security tools -- create clarity in chaos",
    )
    parser.add_argument(
        "--version", action="version", version=f"fenceline {__version__}"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )

    subparsers = parser.add_subparsers(dest="command")

    # -- check --
    check_parser = subparsers.add_parser(
        "check", help="Analyze supply chain security posture"
    )
    check_parser.add_argument(
        "--lockfile", type=str, default=None, help="Path to lockfile"
    )
    check_parser.add_argument(
        "--base-ref", type=str, default=None, help="Git ref to diff against"
    )
    check_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )
    check_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    check_parser.set_defaults(func=_cmd_check)

    # -- install --
    install_parser = subparsers.add_parser(
        "install", help="Monitor a package install in real time"
    )
    install_parser.add_argument(
        "--sandbox",
        action="store_true",
        help="Run install in Docker container (requires Docker). "
             "Blocks install if suspicious network activity is detected.",
    )
    install_parser.add_argument(
        "--monitor-time",
        type=int,
        default=60,
        help="Seconds to monitor network after install completes (default: 60)",
    )
    install_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    install_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run (e.g., npm install)",
    )
    install_parser.set_defaults(func=_cmd_install)

    # -- init --
    init_parser = subparsers.add_parser(
        "init", help="Initialize fenceline config in current project"
    )
    init_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing config"
    )
    init_parser.set_defaults(func=_cmd_init)

    # -- audit-actions --
    audit_actions_parser = subparsers.add_parser(
        "audit-actions",
        help="Scan GitHub Actions workflows for supply chain risks (tag tampering, etc.)",
    )
    audit_actions_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Path to project root (default: current directory)",
    )
    audit_actions_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show all findings including skipped"
    )
    audit_actions_parser.set_defaults(func=_cmd_audit_actions)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
