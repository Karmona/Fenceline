"""Allow running fenceline as a module: python -m fenceline."""

from fenceline.cli import main
import sys

sys.exit(main())
