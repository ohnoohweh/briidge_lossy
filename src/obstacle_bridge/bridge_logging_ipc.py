"""Best-effort UDP log carriage and a small standalone log receiver.

The sender deliberately has no retries, queue, or blocking fallback.  A log
datagram is optional observability data; losing it must not affect forwarding.
"""
from __future__ import annotations

import argparse
import json
import logging
import select
import socket
from typing import Any, Optional, Tuple

LOG_WIRE_VERSION = 1
DEFAULT_MAX_DATAGRAM_BYTES = 60 * 1024
DEFAULT_ADMIN_QUERY_TIMEOUT_SEC = 0.15
_admin_query_client: Optional["UdpLogQueryClient"] = None


def parse_udp_endpoint(value: str, *, allow_zero: bool = False) -> Tuple[str, int]:
    """Parse ``host:port`` or ``[ipv6-address]:port`` without DNS I/O."""
    text = str(value or "").strip()
    if text.startswith("["):
        host, separator, port_text = text[1:].partition("]:")
        if not separator:
            raise ValueError("expected [ipv6-address]:port")
    else:
        host, separator, port_text = text.rpartition(":")
        if not separator or not host:
            raise ValueError("expected host:port")
    port = int(port_text)
    if not (0 <= port < 65536 and (allow_zero or port != 0)):
        raise ValueError("port must be in %s..65535" % ("0" if allow_zero else "1"))
    return host, port


class NonBlockingUdpLogHandler(logging.Handler):
    """Serialize records to one UDP socket, dropping all send-side failures."""

    def __init__(self, target: str, max_datagram_bytes: int = DEFAULT_MAX_DATAGRAM_BYTES):
        super().__init__()
        self.target = str(target)
        self.max_datagram_bytes = max(512, min(int(max_datagram_bytes), 65507))
        self.dropped_records = 0
        host, port = parse_udp_endpoint(self.target)
        # Address resolution happens once during configuration, never in emit().
        family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        self._socket = socket.socket(family, socket.SOCK_DGRAM)
        self._socket.setblocking(False)
        self._socket.connect(address)

    def _payload(self, record: logging.LogRecord) -> bytes:
        try:
            message = record.getMessage()
        except Exception:
            message = "<unformattable log message>"
        payload: dict[str, Any] = {
            "v": LOG_WIRE_VERSION,
            "created": record.created,
            "name": str(record.name)[:256],
            "level": record.levelname,
            "levelno": record.levelno,
            "message": message,
            "process": record.process,
            "thread": str(record.threadName)[:256],
        }
        if record.exc_info:
            try:
                payload["exception"] = logging.Formatter().formatException(record.exc_info)
            except Exception:
                payload["exception"] = "<exception formatting failed>"
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=repr).encode("utf-8")
        if len(encoded) <= self.max_datagram_bytes:
            return encoded
        payload.pop("exception", None)
        payload["message"] = str(message) + " [truncated]"
        while payload["message"]:
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=repr).encode("utf-8")
            if len(encoded) <= self.max_datagram_bytes:
                return encoded
            payload["message"] = payload["message"][: len(payload["message"]) // 2]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=repr).encode("utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._socket.send(self._payload(record))
        except Exception:
            self.dropped_records += 1

    def close(self) -> None:
        try:
            self._socket.close()
        except Exception:
            pass
        super().close()


class UdpLogQueryClient:
    """Bounded Admin-Web client for recent lines owned by a UDP receiver."""

    def __init__(self, target: str, timeout_sec: float = DEFAULT_ADMIN_QUERY_TIMEOUT_SEC):
        self.target = str(target)
        self.timeout_sec = max(0.01, min(float(timeout_sec), 0.5))
        host, port = parse_udp_endpoint(self.target)
        self._family, _, _, _, self._address = socket.getaddrinfo(
            host, port, type=socket.SOCK_DGRAM
        )[0]

    def fetch(self, limit: int) -> dict[str, Any]:
        """Return a status payload; receiver and transport errors are data."""
        requested_limit = max(1, min(int(limit), 1000))
        request = json.dumps(
            {"v": LOG_WIRE_VERSION, "kind": "logs.query", "limit": requested_limit},
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            with socket.socket(self._family, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                sock.connect(self._address)
                sock.send(request)
                readable, _, _ = select.select([sock], [], [], self.timeout_sec)
                if not readable:
                    return {"available": False, "lines": [], "error": "logger unavailable"}
                data = sock.recv(DEFAULT_MAX_DATAGRAM_BYTES)
            payload = json.loads(data.decode("utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("v") != LOG_WIRE_VERSION
                or payload.get("kind") != "logs.reply"
                or not payload.get("ok")
                or not isinstance(payload.get("lines"), list)
            ):
                raise ValueError("invalid logger response")
            return {"available": True, "lines": [str(line) for line in payload["lines"]], "error": ""}
        except Exception:
            return {"available": False, "lines": [], "error": "logger unavailable"}


def configure_admin_log_query(target: Optional[str]) -> bool:
    """Resolve the query endpoint at logging setup, not in an Admin request."""
    global _admin_query_client
    _admin_query_client = None
    if not target:
        return False
    try:
        _admin_query_client = UdpLogQueryClient(str(target))
        return True
    except Exception:
        return False


def fetch_remote_log_lines(limit: int) -> Optional[dict[str, Any]]:
    if _admin_query_client is None:
        return None
    return _admin_query_client.fetch(limit)


class UdpLogReceiver:
    """Receive JSON log datagrams and deliver them to local logging handlers."""

    def __init__(self, bind: str, max_datagram_bytes: int = DEFAULT_MAX_DATAGRAM_BYTES):
        host, port = parse_udp_endpoint(bind, allow_zero=True)
        family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM, flags=socket.AI_PASSIVE)[0]
        self._socket = socket.socket(family, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(address)
        self._socket.setblocking(False)
        self.max_datagram_bytes = max(512, min(int(max_datagram_bytes), 65507))
        self.malformed_datagrams = 0

    def handle_datagram(self, data: bytes, address=None) -> bool:
        try:
            payload = json.loads(data.decode("utf-8"))
            if payload.get("v") == LOG_WIRE_VERSION and payload.get("kind") == "logs.query":
                if address is None:
                    raise ValueError("query sender missing")
                limit = max(1, min(int(payload.get("limit", 400)), 1000))
                lines = [str(line) for line in list(_debug_log_ring())[-limit:]]
                reply_payload = {"v": LOG_WIRE_VERSION, "kind": "logs.reply", "ok": True, "lines": lines}
                reply = json.dumps(reply_payload, ensure_ascii=False, separators=(",", ":"), default=repr).encode("utf-8")
                while len(reply) > self.max_datagram_bytes and lines:
                    lines.pop(0)
                    reply_payload["lines"] = lines
                    reply = json.dumps(reply_payload, ensure_ascii=False, separators=(",", ":"), default=repr).encode("utf-8")
                self._socket.sendto(reply, address)
                return True
            if not isinstance(payload, dict) or payload.get("v") != LOG_WIRE_VERSION:
                raise ValueError("unsupported log wire payload")
            record = logging.makeLogRecord({
                "name": str(payload.get("name", "remote")),
                "levelno": int(payload.get("levelno", logging.INFO)),
                "levelname": str(payload.get("level", "INFO")),
                "msg": str(payload.get("message", "")),
                "created": float(payload.get("created", 0.0)),
                "process": int(payload.get("process", 0)),
                "threadName": str(payload.get("thread", "remote")),
            })
            exception = payload.get("exception")
            if exception:
                record.msg = "%s\n%s" % (record.msg, str(exception))
            logging.getLogger().handle(record)
            return True
        except Exception:
            self.malformed_datagrams += 1
            return False

    def serve_forever(self) -> None:
        while True:
            readable, _, _ = select.select([self._socket], [], [])
            if readable:
                data, _ = self._socket.recvfrom(self.max_datagram_bytes)
                self.handle_datagram(data, _)


def _debug_log_ring():
    # Imported lazily to avoid the configurator/receiver import cycle.
    from .bridge_debug_logging import DEBUG_LOG_RING

    return DEBUG_LOG_RING


def main(argv: Optional[list[str]] = None) -> int:
    from .bridge_debug_logging import DebugLoggingConfigurator

    parser = argparse.ArgumentParser(description="ObstacleBridge best-effort UDP log receiver")
    parser.add_argument("--bind", default="127.0.0.1:15140", help="UDP listen address (default 127.0.0.1:15140)")
    parser.add_argument("--max-datagram-bytes", type=int, default=DEFAULT_MAX_DATAGRAM_BYTES)
    DebugLoggingConfigurator.register_cli(parser)
    args = parser.parse_args(argv)
    DebugLoggingConfigurator.from_args(args).apply()
    receiver = UdpLogReceiver(args.bind, args.max_datagram_bytes)
    logging.getLogger("logging_ipc").info("UDP log receiver listening on %s", args.bind)
    receiver.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
