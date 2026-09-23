"""Redacted local operator evidence for telemetry spool/collector state."""
from __future__ import annotations

import argparse
import json
from typing import Iterable, Optional

from .bridge_telemetry import TelemetrySpool


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Show redacted telemetry spool state")
    parser.add_argument("--spool-directory", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(TelemetrySpool(args.spool_directory).status(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
