"""TLS-only, local-reference telemetry/v1 ingest service (P3)."""
from __future__ import annotations

import argparse
import http.server
import json
import ssl
from typing import Any, Dict, Iterable, Mapping, Optional

from .bridge_telemetry import MAX_BATCH_EVENTS, MAX_EVENT_BYTES, TelemetrySpool, TelemetryValidationError, validate_event

MAX_REQUEST_BYTES = MAX_EVENT_BYTES * MAX_BATCH_EVENTS


class TelemetryIngestStore:
    """Durably accepts one validated batch before reporting acknowledgement."""

    def __init__(self, spool_directory: str):
        self.spool = TelemetrySpool(spool_directory)
        self.accepted_batches = 0
        self.rejected_batches = 0

    def accept(self, payload: bytes) -> Dict[str, Any]:
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
            if not self.spool.append_many(normalized):
                raise TelemetryValidationError("durable queue unavailable")
        except Exception as exc:
            self.rejected_batches += 1
            if isinstance(exc, TelemetryValidationError):
                raise
            raise TelemetryValidationError("malformed batch") from exc
        self.accepted_batches += 1
        return {"ok": True, "accepted_through": sequences[-1], "accepted_count": len(normalized)}

    def health(self) -> Dict[str, Any]:
        return {"ok": True, "accepted_batches": self.accepted_batches, "rejected_batches": self.rejected_batches}


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
            self._json(202, self.store.accept(self.rfile.read(length)))
        except TelemetryValidationError as exc:
            self._json(400, {"ok": False, "error": str(exc)})


def build_tls_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    if not certfile or not keyfile:
        raise ValueError("TLS certificate and key are required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def serve(bind: str, port: int, spool_directory: str, certfile: str, keyfile: str) -> None:
    server = http.server.ThreadingHTTPServer((bind, int(port)), _Handler)
    server.RequestHandlerClass.store = TelemetryIngestStore(spool_directory)
    server.socket = build_tls_context(certfile, keyfile).wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TLS-only ObstacleBridge telemetry ingest reference")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--spool-directory", required=True)
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    args = parser.parse_args(argv)
    serve(args.bind, args.port, args.spool_directory, args.tls_cert, args.tls_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
