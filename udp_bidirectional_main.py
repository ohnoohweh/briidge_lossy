#!/usr/bin/env python3
"""Legacy compatibility wrapper for the renamed ObstacleBridge entry point."""

from ObstacleBridge import *  # noqa: F401,F403
from ObstacleBridge import main

if __name__ == "__main__":
    main()
