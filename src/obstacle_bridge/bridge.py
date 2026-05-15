#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bidirectional overlay with multiplexed UDP+TCP fan-in/fan-out over one reliable Session.

ChannelMux (shim between Runner and Session):
- Offers UDP and TCP server sockets simultaneously (multi-client).
- TCP channels carry OPEN/DATA/CLOSE control.
- UDP channels are created on first datagram from a client and expire after 20s idle.
- Client roles use dynamic (ephemeral) ports on the local side by default.

Overlay/Session synchronization:
- DISCONNECTED:
  * Stop accepting new UDP/TCP connections
  * Close all existing UDP/TCP channels and clear mappings
  * Drop any outbound mux payloads (guarded by PROTO.is_connected()).
- CONNECTED: (re)start listeners and resume accepting.

CLI (streamlined defaults):
- UDP server: listen on [::]:16666
- UDP client: target 127.0.0.1:16666, bind 0.0.0.0 (ephemeral port)
- TCP server: listen on [::]:3128
- TCP client: target 127.0.0.1:3128, bind 0.0.0.0 (ephemeral port)

Instructions to AI for changes: 
- Convert to Python 3.9 compatibility only.
- Touch as few lines as possible.
- Keep architecture proper
- No cleanup, no refactor, no style changes, no logic changes.
- Only replace Python >3.9 syntax with 3.9-safe equivalents.
- Return a patch or only the exact modified lines.

Reliability/RTT is handled by Session/PeerProtocol in this module.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import pathlib
import sys
import time
import ctypes
try:
    import fcntl
except Exception:
    fcntl = None
import inspect
from contextlib import contextmanager
import enum
import importlib.util
import ipaddress
import logging
import logging.handlers
import socket
import struct
import zlib  # for CRC32 counters (TX/RX running CRCs)
import contextlib
import mimetypes
import random
import hashlib
import hmac
import secrets
import subprocess
from datetime import datetime, timezone
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from collections import deque
from typing import Dict, Optional, Tuple, List, Set, Deque, Any, Callable, Literal


def _bridge_import_debug(event: str, **fields: Any) -> None:
    path = str(os.environ.get("OBSTACLEBRIDGE_BRIDGE_IMPORT_DEBUG_LOG") or "").strip()
    if not path:
        return
    try:
        payload = {
            "event": event,
            "time": time.time(),
            **fields,
        }
        target = pathlib.Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True, default=repr) + "\n")
    except Exception:
        pass


_bridge_import_debug("bridge_import_entered")

if sys.platform.startswith("win"):
    from ctypes import wintypes
else:
    wintypes = None

_bridge_import_debug("bridge_import_after_ctypes", platform=sys.platform)

try:
    _bridge_import_debug("bridge_import_before_crypto_extract")
    from .crypto_extract import (
        AESGCM,
        ChaCha20Poly1305,
        HKDF,
        PBKDF2HMAC,
        available_crypto_extract,
        ed25519,
        hashes,
        serialization,
        x25519,
    )
    _bridge_import_debug("bridge_import_after_crypto_extract", backend=str(available_crypto_extract().get("backend", "")))
except Exception:
    hashes = None
    AESGCM = None
    ChaCha20Poly1305 = None
    HKDF = None
    PBKDF2HMAC = None
    serialization = None
    ed25519 = None
    x25519 = None

    def available_crypto_extract() -> dict:
        return {"backend": "unavailable"}
    _bridge_import_debug("bridge_import_crypto_extract_failed")


CONFIG_SECRET_FIELDS = {"admin_web_password", "secure_link_psk"}
CONFIG_SECRET_PREFIX = "enc:v1:"
CONFIG_SECRET_SALT = b"ObstacleBridge config secret v1"
CONFIG_SECRET_INFO = b"ObstacleBridge config field encryption"
CONFIG_SECRET_AAD = b"ObstacleBridge cfg secret"
ADMIN_SECRET_REVEAL_AAD = b"ObstacleBridge WebAdmin secret reveal v1"
ADMIN_SECRET_REVEAL_ITERATIONS = 200000
RESTART_EXIT_CODE_IMMEDIATE = 75
RESTART_EXIT_CODE_DELAYED = 77
_BUILD_INFO_CACHE: Optional[dict] = None


def _config_secret_seed() -> bytes:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if text:
            return text.encode("utf-8")
    try:
        return socket.gethostname().encode("utf-8")
    except Exception:
        return b"obstacle-bridge"


def _derive_config_secret_key() -> bytes:
    if hashes is None or HKDF is None:
        raise RuntimeError("config secret encryption requires cryptography or the iOS native crypto backend")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=CONFIG_SECRET_SALT,
        info=CONFIG_SECRET_INFO,
    )
    return hkdf.derive(_config_secret_seed())


def _detect_build_info() -> dict:
    global _BUILD_INFO_CACHE
    if _BUILD_INFO_CACHE is not None:
        return dict(_BUILD_INFO_CACHE)
    info = {
        "commit": "unknown",
        "source": "git",
        "repo_root": "",
        "tainted": False,
        "tracked_changes": 0,
        "untracked_changes": 0,
        "available": False,
    }
    try:
        from .build_info import BUILD_COMMIT, BUILD_DIFF_SHA, BUILD_DIRTY, BUILD_SOURCE

        commit = str(BUILD_COMMIT or "").strip()
        if commit:
            info.update(
                {
                    "commit": commit,
                    "source": str(BUILD_SOURCE or "embedded"),
                    "diff_sha": str(BUILD_DIFF_SHA or ""),
                    "repo_root": "",
                    "tainted": bool(BUILD_DIRTY),
                    "available": True,
                }
            )
            _BUILD_INFO_CACHE = dict(info)
            return dict(info)
    except Exception:
        pass
    try:
        repo_root = pathlib.Path(__file__).resolve().parents[2]
    except Exception:
        repo_root = None
    if repo_root is not None:
        try:
            rev = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if rev.returncode == 0:
                info["commit"] = str(rev.stdout or "").strip() or "unknown"
                info["repo_root"] = str(repo_root)
                info["available"] = True
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if status.returncode == 0:
                tracked = 0
                untracked = 0
                for line in str(status.stdout or "").splitlines():
                    item = line.strip()
                    if not item:
                        continue
                    if item.startswith("??"):
                        untracked += 1
                    else:
                        tracked += 1
                info["tracked_changes"] = tracked
                info["untracked_changes"] = untracked
                info["tainted"] = bool(tracked or untracked)
        except Exception:
            pass
    _BUILD_INFO_CACHE = dict(info)
    return dict(info)


def _runtime_dependency_status() -> dict:
    crypto_status = available_crypto_extract()
    packages = {
        "cryptography": {
            "available": bool(hashes and ChaCha20Poly1305 and HKDF),
            "purpose": "configuration secret encryption and secure-link cryptography",
        },
        "aioquic": {
            "available": importlib.util.find_spec("aioquic") is not None,
            "purpose": "QUIC overlay transport",
        },
        "websockets": {
            "available": importlib.util.find_spec("websockets") is not None,
            "purpose": "WebSocket overlay transport",
        },
    }
    missing = [name for name, item in packages.items() if not item["available"]]
    return {
        "ok": not missing,
        "missing": missing,
        "packages": packages,
        "crypto_extract": crypto_status,
        "install_hint": "python3 -m pip install -e .",
    }


def _admin_ui_platform() -> str:
    override = str(os.environ.get("OBSTACLEBRIDGE_ADMIN_UI_PLATFORM") or "").strip()
    if override:
        return override
    return str(sys.platform or "")


def _runtime_dependency_status_for_platform(platform: str | None = None) -> dict:
    status = _runtime_dependency_status()
    normalized = str(platform or _admin_ui_platform()).strip().lower()
    if normalized == "ios":
        return {
            **status,
            "ok": True,
            "missing": [],
            "install_hint": "",
        }
    return status


def _encrypt_config_secret(value: Any) -> Any:
    if not isinstance(value, str) or value == "":
        return value
    if ChaCha20Poly1305 is None:
        raise RuntimeError(
            "config secret encryption requires cryptography or the iOS native crypto backend; "
            f"crypto_extract={available_crypto_extract()!r}"
        )
    key = _derive_config_secret_key()
    nonce = secrets.token_bytes(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, value.encode("utf-8"), CONFIG_SECRET_AAD)
    token = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return CONFIG_SECRET_PREFIX + token


def _decrypt_config_secret(value: Any) -> Any:
    if not isinstance(value, str) or not value.startswith(CONFIG_SECRET_PREFIX):
        return value
    if ChaCha20Poly1305 is None:
        raise RuntimeError(
            "config secret decryption requires cryptography or the iOS native crypto backend; "
            f"crypto_extract={available_crypto_extract()!r}"
        )
    raw = base64.urlsafe_b64decode(value[len(CONFIG_SECRET_PREFIX):].encode("ascii"))
    if len(raw) < 13:
        raise ValueError("invalid encrypted config secret")
    nonce, ciphertext = raw[:12], raw[12:]
    key = _derive_config_secret_key()
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, CONFIG_SECRET_AAD)
    return plaintext.decode("utf-8")


def _transform_config_secrets(obj: Any, transform: Callable[[Any], Any]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key in CONFIG_SECRET_FIELDS:
                out[key] = transform(value)
            else:
                out[key] = _transform_config_secrets(value, transform)
        return out
    if isinstance(obj, list):
        return [_transform_config_secrets(item, transform) for item in obj]
    return obj

# ===== ANSI sequences (dashboard) =====
ANSI_HIDE_CURSOR = "\x1b[?25l"
ANSI_SHOW_CURSOR = "\x1b[?25h"
ANSI_HOME_CLEAR = "\x1b[H\x1b[J"
DEFAULT_ADMIN_WEB_LOG_MAX_LINES = 1200
DEBUG_LOG_RING: Deque[str] = deque(maxlen=DEFAULT_ADMIN_WEB_LOG_MAX_LINES)


def configure_debug_log_ring(max_lines: int) -> None:
    global DEBUG_LOG_RING
    limit = max(1, int(max_lines))
    DEBUG_LOG_RING = deque(DEBUG_LOG_RING, maxlen=limit)


def format_stream_endpoints(writer: Any) -> str:
    try:
        local = writer.get_extra_info("sockname")
    except Exception:
        local = None
    try:
        peer = writer.get_extra_info("peername")
    except Exception:
        peer = None
    return f"local={local} peer={peer}"

# ============================== Logging / Debug Config ===============================
def debug_print(msg: str):
    """Write a timestamped debug line to stderr, never crashing."""
    try:
        now = time.time()
        t = time.localtime(now)
        ms = int((now - int(now)) * 1000)
        ts = f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.{ms:03d}"
        sys.stderr.write(f"[{ts}] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass

class DebugToStderrHandler(logging.Handler):
    """
    Logging handler that routes DEBUG (and below) to debug_print().
    INFO+ will continue through the normal logging config (stdout).
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Only mirror DEBUG (and NOT higher levels) to the debug area.
            if record.levelno <= logging.DEBUG:
                msg = self.format(record)
                debug_print(msg)
        except Exception:
            pass


class InMemoryDebugLogHandler(logging.Handler):
    """Capture formatted log lines in a ring buffer for admin web debug tab."""
    def emit(self, record: logging.LogRecord) -> None:
        try:
            DEBUG_LOG_RING.append(self.format(record))
        except Exception:
            pass


from .bridge_debug_logging import (
    DEBUG_LOG_RING,
    DebugLoggingConfigurator,
    DebugToStderrHandler,
    InMemoryDebugLogHandler,
    configure_debug_log_ring,
    debug_print,
)

# === ISession abstraction and UDP adapter (Milestone A; no behavior change) ===
# Keeps everything in this file; UdpSession simply packages the existing Session+PeerProtocol
# while exposing a small, transport-agnostic surface for ChannelMux and Runner.  
from typing import Protocol, Callable, Optional, Awaitable

@dataclass
class SessionMetrics:
    # RTT (if known)
    rtt_sample_ms: Optional[float] = None
    rtt_est_ms:    Optional[float] = None
    last_rtt_ok_ns: Optional[int]  = None
    # Congestion / flow stats (if known)
    inflight: Optional[int]        = None
    max_inflight: Optional[int]    = None
    waiting_count: Optional[int]   = None
    last_ack_peer: Optional[int]   = None
    last_sent_ctr: Optional[int]   = None
    expected: Optional[int]        = None
    peer_missed_count: Optional[int] = None
    our_missed_count: Optional[int]  = None

class ISession(Protocol):
    # lifecycle
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def wait_connected(self, timeout: Optional[float] = None) -> bool: ...
    def is_connected(self) -> bool: ...

    # application payload (Mux -> Session)
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int: ...
    def get_max_app_payload_size(self) -> int: ...

    # callback wiring
    def set_on_app_payload(self, cb: Callable[[bytes], None]) -> None: ...
    def set_on_state_change(self, cb: Callable[[bool], None]) -> None: ...
    def set_on_peer_rx(self, cb: Callable[[int], None]) -> None: ...
    def set_on_peer_tx(self, cb: Callable[[int], None]) -> None: ...
    # optional: peer label
    def set_on_peer_set(self, cb: Callable[[str, int], None]) -> None: ...

    # (Milestone A helper so Runner can keep its meters identical)
    def set_on_app_from_peer_bytes(self, cb: Callable[[int], None]) -> None: ...
    def set_on_transport_epoch_change(self, cb: Callable[[int], None]) -> None: ...

    def get_metrics(self) -> SessionMetrics: ...



from .bridge_transport_udp import (
    BaseFrame,
    BaseFrameV2,
    Protocol,
    ProtocolRuntime,
    PROTO,
    MAGIC,
    PTYPE_DATA,
    PTYPE_CONTROL,
    UDP_FRAME_SIZE,
    DATA_UNPADDED_HEADER_SIZE,
    CONTROL_MAX_MISSED,
    DATA_MAX_CHUNK,
    FRAME_FIRST,
    FRAME_CONT,
    now_ns,
    _monotonic_age_seconds_from_ns,
    ring_cmp,
    c16_inc,
    c16_dec,
    c16_range,
    highest_ring,
    ahead_distance,
    DataPacket,
    ControlPacket,
    Reassembly,
    SendPort,
    Session,
    PeerProtocol,
    UdpSession,
)

from .bridge_securelink import (
    _SecureLinkIdentity,
    _SecureLinkPeerState,
    _secure_link_canonical_cert_body_bytes,
    _secure_link_parse_timestamp,
    _secure_link_load_signature_bytes,
    _secure_link_load_revoked_serials,
    _secure_link_public_key_der_b64_to_obj,
    _secure_link_load_identity_from_paths,
    _secure_link_validate_local_identity_operational,
    SecureLinkPskSession,
)

from .bridge_compression import CompressLayerSession

from .bridge_transport_common import (
    StreamRTT,
    StreamRTTRuntime,
    _bind_family_constraint,
    _has_configured_overlay_peer,
    _host_ip_family,
    _ipv4_to_mapped_ipv6,
    _listener_family_for_host,
    _localhost_fallback,
    _overlay_cli_attrs,
    _peer_resolve_mode,
    _prefer_unspec_listener_family,
    _resolve_hostalias,
    _resolve_cli_peer,
    _resolve_peer_endpoint,
    _strip_brackets,
    _wildcard_host_for_family,
)
from .bridge_transport_tcp import TcpStreamSession
from .bridge_transport_quic import QuicSession
from .bridge_transport_ws import (
    WebSocketBase64PayloadCodec,
    WebSocketBinaryPayloadCodec,
    WebSocketJsonBase64PayloadCodec,
    WebSocketPayloadCodec,
    WebSocketSemiTextShapePayloadCodec,
    WebSocketSession,
    _WsConnectionBootstrapError,
)
from .bridge_channelmux import (
    STATE_CONNECTED,
    STATE_DISCONNECTED,
    STATE_FAILED,
    _ChanCtr,
    ChannelMux,
)
from .bridge_webadmin import AdminWebUI
from .bridge_stats import StatsBoard

from .bridge_runner import (
    RunnerMuxAggregate,
    Runner,
    ConfigAwareCLI,
    RUNTIME_CLI_DESCRIPTION,
    default_runtime_registrars,
    parse_runtime_args,
    build_runtime_args_from_config,
    main,
)
