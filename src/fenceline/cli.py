"""Fenceline CLI entry point."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__


def _cmd_check(args: argparse.Namespace) -> int:
    from .check.scanner import run
    return run(args)


def _cmd_install(args: argparse.Namespace) -> int:
    from .install.wrapper import run
    return run(args)


def _cmd_wrap(args: argparse.Namespace) -> int:
    from .wrap import run
    return run(args)


def _cmd_init(args: argparse.Namespace) -> int:
    from .init.hooks import run
    return run(args)


def _cmd_audit_actions(args: argparse.Namespace) -> int:
    from .actions.audit import run
    return run(args)


def _cmd_map(args: argparse.Namespace) -> int:
    from .map_check import run
    return run(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fenceline",
        description="Dependency firewall for developer machines",
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

    # -- wrap (hero workflow — listed first) --
    wrap_parser = subparsers.add_parser(
        "wrap",
        help="Activate the dependency firewall — wraps npm/yarn/pnpm to sandbox installs",
    )
    wrap_parser.add_argument(
        "--enable", action="store_true",
        help="Install wrappers (npm install → sandboxed install)",
    )
    wrap_parser.add_argument(
        "--disable", action="store_true",
        help="Remove wrappers (restore original commands)",
    )
    wrap_parser.add_argument(
        "--status", action="store_true",
        help="Show which tools are currently wrapped",
    )
    wrap_parser.set_defaults(func=_cmd_wrap)

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
        "--format",
        choices=["text", "json"],
        default="text",
        dest="output_format",
        help="Output format (default: text). JSON is useful for CI integration.",
    )
    install_parser.add_argument(
        "install_cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (e.g., npm install express)",
    )
    install_parser.set_defaults(func=_cmd_install)

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
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Minimum risk level to fail (exit 1). Default: high.",
    )
    check_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    check_parser.set_defaults(func=_cmd_check)

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

    # -- map --
    map_parser = subparsers.add_parser(
        "map", help="Check or update deep map data (network baselines)",
    )
    map_parser.add_argument(
        "--check", action="store_true",
        help="Validate map data against live DNS",
    )
    map_parser.add_argument(
        "--update", action="store_true",
        help="Update DNS snapshots in map YAML files",
    )
    map_parser.set_defaults(func=_cmd_map)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Respect --no-color and NO_COLOR env var (https://no-color.org/)
    if getattr(args, 'no_color', False) or os.environ.get('NO_COLOR'):
        os.environ['NO_COLOR'] = '1'

    # Configure logging (verbose flag may come from any subcommand)
    from .log import setup_logging
    verbose = getattr(args, 'verbose', False)
    setup_logging(verbose=verbose)

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
