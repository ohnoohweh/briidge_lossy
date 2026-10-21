"""Product-neutral Admin API shapes shared by Python runtime owners.

Keep this public schema aligned with ``ObstacleBridgeAdminAPI`` in Swift Core.
"""
from __future__ import annotations

from typing import Any, Mapping


def logging_worker_status(raw: Mapping[str, Any] | None = None) -> dict[str, Any]:
    source = dict(raw or {})
    state = str(source.get("state", "off") or "off").lower()
    if state not in {"off", "running", "restarting", "unavailable", "stopped"}:
        state = "unavailable"
    def integer(key: str) -> int:
        try: return int(source.get(key, 0) or 0)
        except (TypeError, ValueError): return 0
    return {"state": state, "implementation": str(source.get("implementation", "") or ""), "pid": integer("pid"), "generation": integer("generation"), "restarts": integer("restarts"), "failed_starts": integer("failed_starts"), "dropped_records": integer("dropped_records")}


def logs_payload(*, lines: list[str], available: bool, source: str, error: str = "", logging_worker: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": True, "available": bool(available), "lines": list(lines), "count": len(lines), "source": str(source), "error": str(error or ""), "logging_worker": logging_worker_status(logging_worker)}
