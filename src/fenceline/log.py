"""Logging configuration for Fenceline.

All modules should use::

    from fenceline.log import get_logger
    logger = get_logger(__name__)

User-facing output (BLOCKED messages, alerts, formatted reports) should
still use print() to stdout. Logging goes to stderr so it doesn't
interfere with --format json output.
"""

from __future__ import annotations

import logging
import os
import sys


def setup_logging(verbose: bool = False) -> None:
    """Configure the fenceline logger.

    Called once from cli.main() after parsing args.
    """
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[fenceline] %(message)s"))

    logger = logging.getLogger("fenceline")
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.propagate = False


def get_logger(name: str = "fenceline") -> logging.Logger:
    """Get a logger under the fenceline namespace."""
    if name.startswith("fenceline"):
        return logging.getLogger(name)
    return logging.getLogger(f"fenceline.{name}")
