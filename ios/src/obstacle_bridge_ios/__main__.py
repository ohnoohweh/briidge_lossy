from __future__ import annotations

import json
import sys

from .app import main
from .dependency_spike import run_m2_dependency_spike_sync, write_m2_dependency_spike_report


if __name__ == "__main__":
    if "--m2-dependency-spike" in sys.argv:
        report = run_m2_dependency_spike_sync()
        report_path = write_m2_dependency_spike_report(report)
        print(json.dumps({**report, "report_path": str(report_path)}, indent=2, sort_keys=True))
        raise SystemExit(0 if bool(report.get("ok")) else 1)
    main().main_loop()
