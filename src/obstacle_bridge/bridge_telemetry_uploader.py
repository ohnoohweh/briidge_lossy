"""Single-flight, budgeted mTLS uploader for telemetry/v1 spool events."""
from __future__ import annotations

import json
import random
import ssl
import time
import urllib.error
import urllib.request
from collections import Counter
from typing import Any, Callable, Dict, Optional

from .bridge_telemetry import MAX_BATCH_EVENTS, TelemetrySpool, encode_batch


class TelemetryUploader:
    def __init__(self, spool: TelemetrySpool, endpoint: str, cafile: str, certfile: str, keyfile: str, timeout_sec: float = 5.0, byte_budget_per_day: int = 8 * 1024 * 1024, clock: Callable[[], float] = time.monotonic):
        if not endpoint.startswith("https://"):
            raise ValueError("telemetry endpoint must use HTTPS")
        self.spool, self.endpoint, self.timeout_sec = spool, endpoint, max(0.1, min(float(timeout_sec), 30.0))
        self.byte_budget_per_day, self.clock = max(1024, int(byte_budget_per_day)), clock
        self.context = ssl.create_default_context(cafile=cafile)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self.context))
        self.next_attempt = 0.0
        self.backoff_sec = 1.0
        self.sent_bytes = 0
        self.dropped = Counter()
        self.last_error = ""
        self._in_flight = False

    def _schedule_failure(self, error: str) -> None:
        self.last_error = error
        self.next_attempt = self.clock() + self.backoff_sec + random.uniform(0.0, self.backoff_sec * 0.2)
        self.backoff_sec = min(300.0, self.backoff_sec * 2.0)

    def upload_once(self) -> Dict[str, Any]:
        if self._in_flight or self.clock() < self.next_attempt:
            return {"ok": False, "reason": "backoff"}
        events = self.spool.recover(MAX_BATCH_EVENTS)
        if not events:
            return {"ok": True, "accepted_count": 0}
        identity = (events[0]["installation_id"], events[0]["session_id"])
        events = [event for event in events if (event["installation_id"], event["session_id"]) == identity]
        payload = encode_batch(events)
        if self.sent_bytes + len(payload) > self.byte_budget_per_day:
            self.dropped["byte_budget"] += len(events)
            return {"ok": False, "reason": "byte_budget"}
        self._in_flight = True
        try:
            request = urllib.request.Request(self.endpoint, data=payload, method="POST", headers={"Content-Type": "application/json", "Accept": "application/json"})
            with self._opener.open(request, timeout=self.timeout_sec) as response:
                if response.status != 202:
                    raise RuntimeError("unexpected HTTP status")
                acknowledgement = json.loads(response.read().decode("utf-8"))
            accepted = int(acknowledgement.get("accepted_through", 0))
            if not acknowledgement.get("ok") or accepted < events[0]["sequence"] or accepted > events[-1]["sequence"]:
                raise RuntimeError("invalid acknowledgement")
            removed = self.spool.acknowledge_through(accepted, *identity)
            self.sent_bytes += len(payload)
            self.next_attempt, self.backoff_sec, self.last_error = self.clock(), 1.0, ""
            return {"ok": True, "accepted_count": removed, "accepted_through": accepted}
        except Exception as exc:
            self._schedule_failure(type(exc).__name__)
            return {"ok": False, "reason": "upload_failed"}
        finally:
            self._in_flight = False
