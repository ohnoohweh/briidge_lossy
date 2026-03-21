#!/usr/bin/env python3
"""Compatibility wrapper for the packaged test harness script."""

from pathlib import Path
import asyncio
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scripts.run_udp_bidir_tests import *  # noqa: F401,F403
from scripts.run_udp_bidir_tests import main

if __name__ == "__main__":
    asyncio.run(main())
