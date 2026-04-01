"""Allow running fenceline as a module: python -m fenceline."""

import sys

from fenceline.cli import main

sys.exit(main())
