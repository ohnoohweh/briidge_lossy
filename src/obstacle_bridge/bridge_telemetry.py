"""Bounded, redacted telemetry/v1 event construction for hardened logging."""
from __future__ import annotations

import argparse
import json
import hashlib
import os
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional

TELEMETRY_VERSION = 1
MAX_EVENT_BYTES = 4096
MAX_BATCH_EVENTS = 128
MAX_FIELD_VALUE_LENGTH = 256
PRIORITIES = ("low", "normal", "critical")
ALLOWED_FIELD_NAMES = frozenset(
    {
        "counter",
        "dropped",
        "error_code",
        "load_1m",
        "memory_bytes",
        "queue_depth",
        "reason",
        "state",
        "transport",
    }
)
_SENSITIVE_FIELD_TOKENS = ("address", "cookie", "header", "key", "packet", "payload", "psk", "secret", "token")
_EVENT_KEYS = frozenset(("v", "kind", "installation_id", "session_id", "sequence", "monotonic_ns", "wall_time", "priority", "event", "fields"))


class TelemetryRuntimeSettings:
    """Shared runtime configuration surface for bounded telemetry/v1."""

    @staticmethod
    def register_client_cli(parser: argparse.ArgumentParser) -> None:
        group = parser.add_argument_group("telemetry_client")
        group.add_argument(
            "--telemetry-enabled",
            action="store_true",
            default=False,
            help="Enable bounded HTTPS telemetry outside bridge and packet paths",
        )
        group.add_argument(
            "--telemetry-endpoint",
            default="",
            help="HTTPS collector endpoint for telemetry batches",
        )
        group.add_argument(
            "--telemetry-spool-directory",
            default="",
            help="Local directory for bounded telemetry spool segments",
        )
        group.add_argument(
            "--telemetry-client-certificate-directory",
            default="/etc/obstaclebridge/telemetry-client",
            help="Python uploader directory containing client.cert.pem, client.key.pem, and collector-ca.cert.pem",
        )
        group.add_argument(
            "--telemetry-client-address-family",
            choices=("ipv4", "ipv6", "prefer-ipv6"),
            default="prefer-ipv6",
            help="Python telemetry uploader address-family policy; prefer-ipv6 falls back to IPv4",
        )

    @staticmethod
    def register_server_cli(parser: argparse.ArgumentParser) -> None:
        group = parser.add_argument_group("telemetry_server")
        group.add_argument(
            "--telemetry-collector-enabled",
            action="store_true",
            default=False,
            help="Enable this host's separate HTTPS telemetry collector service",
        )
        group.add_argument(
            "--telemetry-collector-bind",
            default="::",
            help="Collector bind address; the default follows telemetry_collector_address_family",
        )
        group.add_argument(
            "--telemetry-collector-address-family",
            choices=("ipv4", "ipv6", "prefer-ipv6"),
            default="prefer-ipv6",
            help="Collector address-family policy; prefer-ipv6 falls back to IPv4",
        )
        group.add_argument(
            "--telemetry-collector-port",
            type=int,
            default=18443,
            help="Collector HTTPS TCP port",
        )
        group.add_argument(
            "--telemetry-collector-spool-directory",
            default="/var/lib/obstaclebridge/telemetry-ingest",
            help="Collector durable accepted-event and replay-state directory",
        )
        group.add_argument(
            "--telemetry-collector-tls-cert",
            default="/etc/obstaclebridge/telemetry/server.cert.pem",
            help="Collector TLS server certificate PEM path",
        )
        group.add_argument(
            "--telemetry-collector-tls-key",
            default="/etc/obstaclebridge/telemetry/server.key.pem",
            help="Collector TLS server private-key PEM path",
        )
        group.add_argument(
            "--telemetry-collector-client-ca",
            default="/etc/obstaclebridge/telemetry/client-ca.cert.pem",
            help="Trusted telemetry client CA certificate PEM path",
        )
        group.add_argument(
            "--telemetry-collector-revocations",
            default="/var/lib/obstaclebridge/telemetry-ingest/revocations.json",
            help="Collector revoked-client-certificate serial list path",
        )


class TelemetryValidationError(ValueError):
    """Raised when a telemetry/v1 value is outside the redacted contract."""


def _bounded_identifier(value: Any, field_name: str) -> str:
    text = str(value or "")
    if not text or len(text) > 128:
        raise TelemetryValidationError("invalid %s" % field_name)
    return text


def _validate_fields(fields: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(fields, Mapping) or len(fields) > len(ALLOWED_FIELD_NAMES):
        raise TelemetryValidationError("invalid fields")
    clean: Dict[str, Any] = {}
    for key, value in fields.items():
        name = str(key)
        if name not in ALLOWED_FIELD_NAMES or any(token in name.lower() for token in _SENSITIVE_FIELD_TOKENS):
            raise TelemetryValidationError("field is not allowlisted")
        if isinstance(value, bool):
            clean[name] = value
        elif isinstance(value, int):
            clean[name] = value
        elif isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise TelemetryValidationError("non-finite field")
            clean[name] = value
        elif isinstance(value, str) and len(value) <= MAX_FIELD_VALUE_LENGTH:
            clean[name] = value
        else:
            raise TelemetryValidationError("invalid field value")
    return clean


def validate_event(event: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a normalized event or reject every non-redacted schema variant."""
    if not isinstance(event, Mapping) or frozenset(event) != _EVENT_KEYS:
        raise TelemetryValidationError("unexpected event shape")
    if event.get("v") != TELEMETRY_VERSION or event.get("kind") != "telemetry.event":
        raise TelemetryValidationError("unsupported telemetry version")
    sequence = event.get("sequence")
    monotonic_ns = event.get("monotonic_ns")
    wall_time = event.get("wall_time")
    if not isinstance(sequence, int) or sequence <= 0:
        raise TelemetryValidationError("invalid sequence")
    if not isinstance(monotonic_ns, int) or monotonic_ns < 0:
        raise TelemetryValidationError("invalid monotonic time")
    if not isinstance(wall_time, (int, float)) or wall_time < 0:
        raise TelemetryValidationError("invalid wall time")
    priority = str(event.get("priority") or "")
    name = str(event.get("event") or "")
    if priority not in PRIORITIES or not name or len(name) > 96 or not all(c.islower() or c.isdigit() or c in "._-" for c in name):
        raise TelemetryValidationError("invalid event metadata")
    return {
        "v": TELEMETRY_VERSION,
        "kind": "telemetry.event",
        "installation_id": _bounded_identifier(event.get("installation_id"), "installation id"),
        "session_id": _bounded_identifier(event.get("session_id"), "session id"),
        "sequence": sequence,
        "monotonic_ns": monotonic_ns,
        "wall_time": float(wall_time),
        "priority": priority,
        "event": name,
        "fields": _validate_fields(event.get("fields", {})),
    }


def encode_event(event: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(validate_event(event), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES:
        raise TelemetryValidationError("event exceeds byte limit")
    return encoded


def decode_event(payload: bytes) -> Dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) > MAX_EVENT_BYTES:
        raise TelemetryValidationError("invalid event payload")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise TelemetryValidationError("malformed event encoding") from exc
    return validate_event(decoded)


def encode_batch(events: Iterable[Mapping[str, Any]]) -> bytes:
    normalized = [validate_event(event) for event in events]
    if not normalized or len(normalized) > MAX_BATCH_EVENTS:
        raise TelemetryValidationError("invalid batch size")
    encoded = json.dumps({"v": TELEMETRY_VERSION, "kind": "telemetry.batch", "events": normalized}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES * MAX_BATCH_EVENTS:
        raise TelemetryValidationError("batch exceeds byte limit")
    return encoded


class TelemetryEmitter:
    """A fixed-capacity producer whose emit path performs neither I/O nor waits."""

    def __init__(self, installation_id: str, session_id: str, capacity: int = 256):
        self.installation_id = _bounded_identifier(installation_id, "installation id")
        self.session_id = _bounded_identifier(session_id, "session id")
        self.capacity = max(1, int(capacity))
        self._events: Deque[Dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._sequence = 0
        self.dropped = Counter()

    def emit(self, event: str, fields: Optional[Mapping[str, Any]] = None, priority: str = "normal") -> bool:
        """Append one event or drop it immediately; never wait for a consumer."""
        if not self._lock.acquire(blocking=False):
            self.dropped["lock_contended"] += 1
            return False
        try:
            self._sequence += 1
            candidate = {
                "v": TELEMETRY_VERSION,
                "kind": "telemetry.event",
                "installation_id": self.installation_id,
                "session_id": self.session_id,
                "sequence": self._sequence,
                "monotonic_ns": time.monotonic_ns(),
                "wall_time": time.time(),
                "priority": priority,
                "event": event,
                "fields": dict(fields or {}),
            }
            try:
                normalized = validate_event(candidate)
                encode_event(normalized)
            except Exception:
                self.dropped["invalid_event"] += 1
                return False
            if len(self._events) >= self.capacity:
                if priority == "critical":
                    for index, queued in enumerate(self._events):
                        if queued["priority"] == "low":
                            del self._events[index]
                            self.dropped["evicted_low"] += 1
                            break
                    else:
                        self.dropped["queue_full"] += 1
                        return False
                else:
                    self.dropped["queue_full"] += 1
                    return False
            self._events.append(normalized)
            return True
        finally:
            self._lock.release()

    def emit_lifecycle(self, state: str, reason: str = "") -> bool:
        return self.emit("runtime.lifecycle", {"state": state, "reason": reason}, priority="critical")

    def emit_load(self, queue_depth: int, dropped: int, load_1m: float = 0.0, memory_bytes: int = 0) -> bool:
        return self.emit("runtime.load", {"queue_depth": queue_depth, "dropped": dropped, "load_1m": load_1m, "memory_bytes": memory_bytes}, priority="low")

    def drain(self, limit: int = MAX_BATCH_EVENTS) -> List[Dict[str, Any]]:
        if not self._lock.acquire(blocking=False):
            return []
        try:
            count = max(1, min(int(limit), MAX_BATCH_EVENTS, len(self._events)))
            return [self._events.popleft() for _ in range(count)]
        finally:
            self._lock.release()


class TelemetrySpool:
    """Atomic per-event files with bounded priority-aware eviction and recovery."""

    def __init__(self, directory: str, max_bytes: int = 4 * 1024 * 1024, max_files: int = 1024):
        self.directory = Path(directory)
        self.max_bytes = max(MAX_EVENT_BYTES, int(max_bytes))
        self.max_files = max(1, int(max_files))
        self.dropped = Counter()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _suppress_os_error():
            os.chmod(str(self.directory), 0o700)

    def _segments(self) -> List[Path]:
        return sorted(self.directory.glob("event-*.json"))

    @staticmethod
    def _segment_sequence(path: Path) -> int:
        try:
            return int(path.name.split("-", 2)[1])
        except Exception:
            return -1

    @staticmethod
    def _event_key(event: Mapping[str, Any]) -> str:
        identity = "%s\x00%s\x00%s" % (event["installation_id"], event["session_id"], event["sequence"])
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _read_segment(path: Path) -> Dict[str, Any]:
        raw = path.read_bytes()
        wrapped = json.loads(raw.decode("utf-8"))
        if not isinstance(wrapped, dict) or set(wrapped) != {"event", "sha256"}:
            raise TelemetryValidationError("invalid spool segment")
        event_bytes = json.dumps(wrapped["event"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if hashlib.sha256(event_bytes).hexdigest() != wrapped["sha256"]:
            raise TelemetryValidationError("spool checksum mismatch")
        return validate_event(wrapped["event"])

    def _usage(self) -> int:
        return sum(path.stat().st_size for path in self._segments())

    def _evict_for(self, required_bytes: int, priority: str) -> bool:
        segments = self._segments()
        while segments and (len(segments) >= self.max_files or self._usage() + required_bytes > self.max_bytes):
            victim = None
            for candidate in segments:
                try:
                    if self._read_segment(candidate)["priority"] == "low":
                        victim = candidate
                        break
                except Exception:
                    victim = candidate
                    break
            if victim is None:
                self.dropped["spool_full"] += 1
                return False
            with _suppress_os_error():
                victim.unlink()
            self.dropped["evicted_low"] += 1
            segments = self._segments()
        return True

    def _append_normalized(self, normalized: Mapping[str, Any]) -> Optional[Path]:
        try:
            event_bytes = encode_event(normalized)
            wrapped = json.dumps(
                {"event": normalized, "sha256": hashlib.sha256(event_bytes).hexdigest()},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ).encode("utf-8")
        except Exception:
            self.dropped["invalid_event"] += 1
            return None
        if not self._evict_for(len(wrapped), normalized["priority"]):
            return None
        sequence = normalized["sequence"]
        key = self._event_key(normalized)
        final = self.directory / ("event-%020d-%s-%s.json" % (sequence, key, normalized["priority"]))
        temporary = self.directory / (".event-%020d-%s.tmp" % (sequence, key))
        if final.exists():
            self.dropped["duplicate_sequence"] += 1
            return None
        try:
            fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(wrapped)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(temporary), str(final))
            with _suppress_os_error():
                os.chmod(str(final), 0o600)
            return final
        except Exception:
            self.dropped["write_failure"] += 1
            with _suppress_os_error():
                temporary.unlink()
            return None

    def append(self, event: Mapping[str, Any]) -> bool:
        try:
            normalized = validate_event(event)
        except Exception:
            self.dropped["invalid_event"] += 1
            return False
        return self._append_normalized(normalized) is not None

    def append_many(self, events: Iterable[Mapping[str, Any]]) -> bool:
        try:
            normalized = [validate_event(event) for event in events]
        except Exception:
            self.dropped["invalid_event"] += 1
            return False
        written: List[Path] = []
        for event in normalized:
            path = self._append_normalized(event)
            if path is None:
                for created in written:
                    with _suppress_os_error():
                        created.unlink()
                return False
            written.append(path)
        return True

    def recover(self, limit: int = MAX_BATCH_EVENTS) -> List[Dict[str, Any]]:
        recovered: List[Dict[str, Any]] = []
        for segment in self._segments():
            if len(recovered) >= max(1, min(int(limit), MAX_BATCH_EVENTS)):
                break
            try:
                recovered.append(self._read_segment(segment))
            except Exception:
                self.dropped["corrupt_segment"] += 1
                with _suppress_os_error():
                    os.replace(str(segment), str(segment.with_suffix(".corrupt")))
        return recovered

    def acknowledge_through(self, sequence: int, installation_id: Optional[str] = None, session_id: Optional[str] = None) -> int:
        removed = 0
        for segment in self._segments():
            try:
                event = self._read_segment(segment)
            except Exception:
                continue
            identity_matches = (installation_id is None or event["installation_id"] == installation_id) and (session_id is None or event["session_id"] == session_id)
            if identity_matches and self._segment_sequence(segment) <= int(sequence):
                with _suppress_os_error():
                    segment.unlink()
                    removed += 1
        return removed

    def status(self) -> Dict[str, Any]:
        events = self.recover(MAX_BATCH_EVENTS)
        return {
            "pending_events": len(self._segments()),
            "pending_bytes": self._usage(),
            "oldest_sequence": events[0]["sequence"] if events else None,
            "newest_sequence": events[-1]["sequence"] if events else None,
            "priorities": dict(Counter(event["priority"] for event in events)),
            "drops": dict(self.dropped),
        }


class _suppress_os_error:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return bool(exc_type and issubclass(exc_type, OSError))
