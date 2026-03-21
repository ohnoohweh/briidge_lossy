#!/usr/bin/env python3
"""Compatibility wrapper for the packaged extract_udp_debug CLI."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from obstacle_bridge.tools.extract_udp_debug import *  # noqa: F401,F403
from obstacle_bridge.tools.extract_udp_debug import main

if __name__ == "__main__":
    main()
