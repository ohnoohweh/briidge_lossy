from __future__ import annotations

import sys

from .app import main


if __name__ == "__main__":
    result = main(sys.argv[1:])
    if hasattr(result, "main_loop"):
        result.main_loop()
    else:
        raise SystemExit(int(result))
