#!/usr/bin/env python3
"""Compatibility wrapper for the packaged transfer module."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from obstacle_bridge.transfer import *  # noqa: F401,F403
