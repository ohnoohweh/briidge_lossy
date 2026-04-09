"""
Supervisor-style runtime entrypoint for ``python -m obstacle_bridge``.

This module parses launcher-specific options and forwards unknown CLI options
to ``bridge.py``.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from typing import List, Optional, Sequence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ObstacleBridge and restart on project restart exit codes"
    )
    parser.add_argument(
        "--command",
        default=None,
        help=(
            "Command to run (single string; shell-split). "
            "When omitted, the launcher starts: "
            "python -m obstacle_bridge.bridge --config ObstacleBridge.cfg"
        ),
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=30,
        help="Seconds to wait before restarting when exit code == 77",
    )
    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="Do not redirect stdout/stderr to the OS null device (useful for debugging)",
    )
    return parser


def _default_bridge_command(forward_args: Sequence[str]) -> List[str]:
    return [
        sys.executable,
        "-m",
        "obstacle_bridge.bridge",
        "--config",
        "ObstacleBridge.cfg",
        *list(forward_args),
    ]


def _resolve_command(raw_command: Optional[str], forward_args: Sequence[str]) -> List[str]:
    if raw_command:
        return [*shlex.split(raw_command), *list(forward_args)]
    return _default_bridge_command(forward_args)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args, forward_args = parser.parse_known_args(argv)
    cmd = _resolve_command(args.command, forward_args)

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
            if rc == 75:
                continue
            if rc == 77:
                time.sleep(args.interval)
                continue
            return rc
    finally:
        if devnull is not None:
            devnull.close()
