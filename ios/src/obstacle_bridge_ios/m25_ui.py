"""M2.5 minimal UI model and status probe helpers."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any


_TRANSPORT_ATTR_PREFIX = {
    "myudp": "udp",
    "tcp": "tcp",
    "ws": "ws",
    "quic": "quic",
}


@dataclass
class M25Config:
    profile_id: str
    display_name: str
    transport: str
    peer_host: str
    peer_port: int
    local_tcp_port: int
    local_udp_port: int
    target_host: str
    target_tcp_port: int
    target_udp_port: int
    secure_link_mode: str = "off"


def profile_from_m25_config(cfg: M25Config) -> dict[str, Any]:
    transport = str(cfg.transport or "").strip().lower()
    if transport not in _TRANSPORT_ATTR_PREFIX:
        raise ValueError(f"unsupported transport: {transport}")
    peer_host = str(cfg.peer_host or "").strip()
    if not peer_host:
        raise ValueError("peer_host is required")
    if not (1 <= int(cfg.peer_port) <= 65535):
        raise ValueError("peer_port must be between 1 and 65535")

    attr_prefix = _TRANSPORT_ATTR_PREFIX[transport]
    obstacle_bridge = {
        "overlay_transport": transport,
        f"{attr_prefix}_peer": peer_host,
        f"{attr_prefix}_peer_port": int(cfg.peer_port),
        "secure_link_mode": str(cfg.secure_link_mode or "off").strip().lower() or "off",
        "own_servers": [
            {
                "name": "ios-local-tcp",
                "listen": {"protocol": "tcp", "bind": "127.0.0.1", "port": int(cfg.local_tcp_port)},
                "target": {
                    "protocol": "tcp",
                    "host": str(cfg.target_host or "127.0.0.1"),
                    "port": int(cfg.target_tcp_port),
                },
            },
            {
                "name": "ios-local-udp",
                "listen": {"protocol": "udp", "bind": "127.0.0.1", "port": int(cfg.local_udp_port)},
                "target": {
                    "protocol": "udp",
                    "host": str(cfg.target_host or "127.0.0.1"),
                    "port": int(cfg.target_udp_port),
                },
            },
        ],
    }
    return {
        "profile_id": str(cfg.profile_id or "").strip(),
        "display_name": str(cfg.display_name or "").strip(),
        "obstacle_bridge": obstacle_bridge,
        "m25_notes": {
            "localhost_exposure_goal": True,
            "platform_note": (
                "System-wide app traffic (for example Safari) requires Network Extension packet tunnel "
                "work in M3; this M2.5 UI stores config and validates reachability only."
            ),
        },
    }


def tcp_status_probe(host: str, port: int, timeout_sec: float = 2.0) -> dict[str, Any]:
    started = time.perf_counter()
    addr = str(host or "").strip()
    if not addr:
        return {"ok": False, "detail": "host is required", "latency_ms": 0}
    if not (1 <= int(port) <= 65535):
        return {"ok": False, "detail": "port must be between 1 and 65535", "latency_ms": 0}
    try:
        with socket.create_connection((addr, int(port)), timeout=float(timeout_sec)):
            latency_ms = int((time.perf_counter() - started) * 1000)
            return {
                "ok": True,
                "detail": f"TCP connect to {addr}:{int(port)} succeeded",
                "latency_ms": latency_ms,
            }
    except Exception as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": False,
            "detail": f"TCP connect to {addr}:{int(port)} failed: {type(exc).__name__}: {exc}",
            "latency_ms": latency_ms,
        }
