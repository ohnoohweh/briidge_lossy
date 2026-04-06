#!/usr/bin/env python3
"""
Replacement for `scripts/run.sh`.

Runs a command in a loop and restarts it only when it exits with code 75.
If the command exits with any other code, this script exits with that code.

Usage examples:
  python scripts/run.py
  python scripts/run.py --command "./bin/python3 -m obstacle_bridge -c obstacle_bridge.cfg"
  python scripts/run.py --command "python -m obstacle_bridge --config ObstacleBridge.cfg --no-dashboard" --interval 30
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run a command and restart only on exit code 75")
    p.add_argument(
        "--command",
        "-c",
        default=None,
        help="Command to run (given as a single string; will be shell-split). If omitted, uses the current Python: -m obstacle_bridge --config ObstacleBridge.cfg",
    )
    p.add_argument(
        "--interval",
        "-i",
        type=int,
        default=30,
        help="Seconds to wait before restarting when exit code == 75",
    )
    p.add_argument(
        "--no-redirect",
        action="store_true",
        help="Do not redirect stdout/stderr to the OS null device (useful for debugging)",
    )
    args = p.parse_args(argv)

    if args.command:
        cmd = shlex.split(args.command)
    else:
        cmd = [sys.executable, "-m", "obstacle_bridge", "--config", "ObstacleBridge.cfg"]
    devnull = None
    if not args.no_redirect:
        devnull = open(os.devnull, "wb")

    try:
        while True:
            try:
                if devnull is not None:
                    result = subprocess.run(cmd, stdout=devnull, stderr=devnull)
                else:
                    result = subprocess.run(cmd)
            except FileNotFoundError as exc:
                print(f"Command not found: {exc}", file=sys.stderr)
                return 127
            rc = int(result.returncode)
            if rc != 75:
                return rc
            time.sleep(args.interval)
    finally:
        if devnull is not None:
            devnull.close()


if __name__ == "__main__":
    raise SystemExit(main())
