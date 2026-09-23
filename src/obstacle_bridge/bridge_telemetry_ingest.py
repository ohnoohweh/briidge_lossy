"""TLS-only, local-reference telemetry/v1 ingest service (P3)."""
from __future__ import annotations

import argparse
import http.server
import json
import ssl
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from .bridge_telemetry import MAX_BATCH_EVENTS, MAX_EVENT_BYTES, TelemetrySpool, TelemetryValidationError, validate_event
from .bridge_telemetry_credentials import TelemetryRevocationList

MAX_REQUEST_BYTES = MAX_EVENT_BYTES * MAX_BATCH_EVENTS


class TelemetryReplayStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._values = self._load()

    def _load(self) -> Dict[str, int]:
        try:
            return {str(k): int(v) for k, v in json.loads(self.path.read_text(encoding="utf-8")).items()}
        except Exception:
            return {}

    def last(self, identity: str) -> int:
        return self._values.get(identity, 0)

    def advance(self, identity: str, sequence: int) -> None:
        self._values[identity] = int(sequence)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._values, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.replace(str(temporary), str(self.path))


class TelemetryAdmissionControl:
    def __init__(self, capacity: int = 32, refill_per_sec: float = 4.0):
        self.capacity, self.refill_per_sec = max(1, int(capacity)), max(0.1, float(refill_per_sec))
        self._buckets: Dict[str, tuple[float, float]] = {}

    def allow(self, identity: str, source: str, now: Optional[float] = None) -> bool:
        current = time.monotonic() if now is None else now
        key = "%s|%s" % (identity, source)
        tokens, previous = self._buckets.get(key, (float(self.capacity), current))
        tokens = min(float(self.capacity), tokens + max(0.0, current - previous) * self.refill_per_sec)
        if tokens < 1.0:
            self._buckets[key] = (tokens, current)
            return False
        self._buckets[key] = (tokens - 1.0, current)
        return True


class TelemetryIngestStore:
    """Durably accepts one validated batch before reporting acknowledgement."""

    def __init__(self, spool_directory: str, revocations: Optional[TelemetryRevocationList] = None, replay_store: Optional[TelemetryReplayStore] = None, admission: Optional[TelemetryAdmissionControl] = None):
        self.spool = TelemetrySpool(spool_directory)
        self.revocations = revocations
        self.replay_store = replay_store or TelemetryReplayStore(str(Path(spool_directory) / "replay.json"))
        self.admission = admission or TelemetryAdmissionControl()
        self.accepted_batches = 0
        self.rejected_batches = 0

    def accept(self, payload: bytes, installation_id: Optional[str] = None, certificate_serial: Optional[int] = None, source: str = "local") -> Dict[str, Any]:
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_REQUEST_BYTES:
            self.rejected_batches += 1
            raise TelemetryValidationError("invalid request size")
        try:
            batch = json.loads(payload.decode("utf-8"))
            if not isinstance(batch, Mapping) or set(batch) != {"v", "kind", "events"}:
                raise TelemetryValidationError("invalid batch shape")
            events = batch.get("events")
            if batch.get("v") != 1 or batch.get("kind") != "telemetry.batch" or not isinstance(events, list):
                raise TelemetryValidationError("unsupported batch")
            if not events or len(events) > MAX_BATCH_EVENTS:
                raise TelemetryValidationError("invalid batch size")
            normalized = [validate_event(event) for event in events]
            identities = {(event["installation_id"], event["session_id"]) for event in normalized}
            sequences = [event["sequence"] for event in normalized]
            if len(identities) != 1 or sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
                raise TelemetryValidationError("invalid batch ordering")
            if not installation_id or next(iter(identities))[0] != installation_id:
                raise TelemetryValidationError("client identity mismatch")
            if certificate_serial is None or (self.revocations and self.revocations.is_revoked(certificate_serial)):
                raise TelemetryValidationError("client credential rejected")
            identity_key = "%s/%s" % next(iter(identities))
            if not self.admission.allow(identity_key, source):
                raise TelemetryValidationError("admission limited")
            if sequences[0] <= self.replay_store.last(identity_key):
                raise TelemetryValidationError("replayed batch")
            if not self.spool.append_many(normalized):
                raise TelemetryValidationError("durable queue unavailable")
            self.replay_store.advance(identity_key, sequences[-1])
        except Exception as exc:
            self.rejected_batches += 1
            if isinstance(exc, TelemetryValidationError):
                raise
            raise TelemetryValidationError("malformed batch") from exc
        self.accepted_batches += 1
        return {"ok": True, "accepted_through": sequences[-1], "accepted_count": len(normalized)}

    def health(self) -> Dict[str, Any]:
        return {"ok": True, "accepted_batches": self.accepted_batches, "rejected_batches": self.rejected_batches, "spool": self.spool.status()}


class _Handler(http.server.BaseHTTPRequestHandler):
    store: TelemetryIngestStore

    def log_message(self, format: str, *args) -> None:
        return

    def _json(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._json(200, self.store.health())
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/v1/telemetry/batches":
            self._json(404, {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 1 or length > MAX_REQUEST_BYTES:
            self._json(413, {"ok": False, "error": "invalid request size"})
            return
        try:
            certificate = self.connection.getpeercert(binary_form=True)
            if not certificate:
                raise TelemetryValidationError("client credential required")
            parsed = x509.load_der_x509_certificate(certificate)
            attributes = parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(attributes) != 1:
                raise TelemetryValidationError("client identity missing")
            self._json(202, self.store.accept(self.rfile.read(length), attributes[0].value, parsed.serial_number, self.client_address[0]))
        except TelemetryValidationError as exc:
            self._json(401, {"ok": False, "error": str(exc)})


def build_tls_context(certfile: str, keyfile: str, client_ca: str) -> ssl.SSLContext:
    if not certfile or not keyfile or not client_ca:
        raise ValueError("TLS certificate, key, and client CA are required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile=client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def serve(bind: str, port: int, spool_directory: str, certfile: str, keyfile: str, client_ca: str, revocations: str) -> None:
    server = http.server.ThreadingHTTPServer((bind, int(port)), _Handler)
    server.RequestHandlerClass.store = TelemetryIngestStore(spool_directory, TelemetryRevocationList(revocations))
    server.socket = build_tls_context(certfile, keyfile, client_ca).wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TLS-only ObstacleBridge telemetry ingest reference")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--spool-directory", required=True)
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--revocations", required=True)
    args = parser.parse_args(argv)
    serve(args.bind, args.port, args.spool_directory, args.tls_cert, args.tls_key, args.client_ca, args.revocations)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
