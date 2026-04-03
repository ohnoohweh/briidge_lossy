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
import ctypes
from ctypes import wintypes
import enum
import importlib.util
import ipaddress
import logging
import logging.handlers
import socket
import struct
import sys
import time
import zlib  # for CRC32 counters (TX/RX running CRCs)
import contextlib
import json
import mimetypes
import os
import pathlib
import random
import hashlib
import secrets
from dataclasses import dataclass
from collections import deque
from typing import Dict, Optional, Tuple, List, Set, Deque, Any, Callable, Literal

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


class DebugLoggingConfigurator:
    """
    Self-contained logging configurator (Option A):
    - Console handler to STDOUT at --console-level (default INFO)  <-- keeps dashboard non-scrolling
    - Optional file handler (--log-file) at --file-level (default: --log)
    - Optional "route DEBUG to stderr" mirror (DebugToStderrHandler), default OFF
    """

    # ---- CLI integration -----------------------------------------------------------
    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        # Add only if not already present (safe if called multiple times)
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--log'):
            p.add_argument('--log', default='WARNING',
                           help='logging level (default WARNING; try INFO or DEBUG) be aware of --console-level and --file-level')
        if not _has('--log-file'):
            p.add_argument('--log-file', default=None,
                           help='file path to also write logs enabled by --log')
        if not _has('--log-file-max-bytes'):
            p.add_argument('--log-file-max-bytes', type=int, default=0,
                           help='maximum on-disk log file size in bytes before rotation; 0 disables rotation')
        if not _has('--log-file-backup-count'):
            p.add_argument('--log-file-backup-count', type=int, default=5,
                           help='number of rotated log files to keep when --log-file-max-bytes is enabled')

        # NEW: split console/file levels to avoid screen flooding at DEBUG
        if not _has('--console-level'):
            p.add_argument('--console-level', default='INFO',
                           help='console (stdout) logging level (default INFO)')
        if not _has('--file-level'):
            p.add_argument('--file-level', default='DEBUG',
                           help='file logging level (default: same as --log)')

        # Change default: DO NOT mirror DEBUG to stderr unless explicitly requested
        if not _has('--debug-stderr'):
            p.add_argument('--debug-stderr', action='store_true', default=False,
                           help='mirror DEBUG lines to stderr (default: off)')
        if not _has('--admin-web-log-max-lines'):
            p.add_argument('--admin-web-log-max-lines', type=int, default=DEFAULT_ADMIN_WEB_LOG_MAX_LINES,
                           help='maximum number of debug log lines kept in memory for the admin web log view')


    @staticmethod
    def from_args(args: argparse.Namespace) -> "DebugLoggingConfigurator":
        return DebugLoggingConfigurator(
            level_name=getattr(args, 'log', 'WARNING'),
            console_level_name=getattr(args, 'console_level', 'INFO'),
            file_level_name=getattr(args, 'file_level', None),
            file_path=getattr(args, 'log_file', None),
            file_max_bytes=getattr(args, 'log_file_max_bytes', 0),
            file_backup_count=getattr(args, 'log_file_backup_count', 5),
            debug_to_stderr=bool(getattr(args, 'debug_stderr', False)),
            admin_web_log_max_lines=getattr(args, 'admin_web_log_max_lines', DEFAULT_ADMIN_WEB_LOG_MAX_LINES),
        )
        # capture per-section log overrides into the object
        for k, v in vars(args).items():
            if k.startswith("log_"):
                setattr(obj, k, v)
        return obj
        
    @staticmethod
    def add_per_section_log_options(p: argparse.ArgumentParser, sections: list[str]):
        for sec in sections:
            opt = f"--log-{sec.replace('_', '-')}"
            p.add_argument(opt, default=None,
                help=f"Override log level for component '{sec}' (e.g. DEBUG, INFO, WARNING)")

    @staticmethod
    def debug_logger_status(lg: logging.Logger):
        """Emit diagnostics showing how logger activation behaved."""

        
        # Emit activation report (always via INFO to guarantee visibility)
        root = logging.getLogger()
        root.info(f"[LOGCFG]   Logger '{lg.name}' ")
        root.info(f"[LOGCFG]   Effective level: {logging.getLevelName(lg.getEffectiveLevel())}")
        root.info(f"[LOGCFG]   Explicit level:  {logging.getLevelName(lg.level)}")
        root.info(f"[LOGCFG]   Handlers:        {len(lg.handlers)} (root={len(root.handlers)})")
        root.info(f"[LOGCFG]   Propagate:       {lg.propagate}")


    # ---- lifecycle ----------------------------------------------------------------
    def __init__(self, level_name: str = 'WARNING',
                 console_level_name: str = 'INFO',
                 file_level_name: Optional[str] = None,
                 file_path: Optional[str] = None,
                 file_max_bytes: int = 0,
                 file_backup_count: int = 5,
                 debug_to_stderr: bool = False,
                 admin_web_log_max_lines: int = DEFAULT_ADMIN_WEB_LOG_MAX_LINES):
        self.level_name = (level_name or 'WARNING').upper()
        self.console_level_name = (console_level_name or 'INFO').upper()
        self.file_level_name = (file_level_name.upper() if file_level_name else None)
        self.file_path = file_path
        self.file_max_bytes = max(0, int(file_max_bytes))
        self.file_backup_count = max(0, int(file_backup_count))
        self.debug_to_stderr = debug_to_stderr
        self.admin_web_log_max_lines = max(1, int(admin_web_log_max_lines))

    def apply(self) -> logging.Logger:
        """
        Configure the root logger:
        - remove any preexisting handlers (to avoid duplicates)
        - add console (stdout) handler at --console-level
        - add optional file handler at --file-level (default --log)
        - add optional DebugToStderrHandler for DEBUG mirroring
        Returns the root logger.
        """
        root = logging.getLogger()

        # Clear any default handlers to avoid duplicates when embedding
        while root.handlers:
            try:
                root.handlers.pop()
            except Exception:
                break

        # Levels and format
        root_level = logging.DEBUG  # capture everything; handlers will filter
        console_level = getattr(logging, self.console_level_name, logging.INFO)
        file_level = getattr(logging, (self.file_level_name or self.level_name), logging.WARNING)
        root.setLevel(root_level)
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        configure_debug_log_ring(self.admin_web_log_max_lines)


        # Optional file handler (can be DEBUG)
        if self.file_path:
            try:
                if self.file_max_bytes > 0:
                    fh = logging.handlers.RotatingFileHandler(
                        self.file_path,
                        maxBytes=self.file_max_bytes,
                        backupCount=max(1, self.file_backup_count),
                        encoding="utf-8",
                    )
                else:
                    fh = logging.FileHandler(self.file_path, encoding="utf-8")
                fh.setLevel(file_level)
                fh.setFormatter(fmt)
                root.addHandler(fh)
            except Exception as e:
                sys.stderr.write(f'Failed to open log file {self.file_path}: {e}\n')
                sys.stderr.flush()

        # Console handler -> STDOUT (quiet by default)
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setLevel(console_level)
        ch.setFormatter(fmt)
        root.addHandler(ch)

        # In-memory ring used by admin web /api/logs.
        mem = InMemoryDebugLogHandler()
        mem.setLevel(logging.DEBUG)
        mem.setFormatter(fmt)
        root.addHandler(mem)


        # Optional: route DEBUG to stderr without affecting global level
        if self.debug_to_stderr:
            try:
                dbg_handler = DebugToStderrHandler()
                dbg_handler.setLevel(logging.DEBUG)
                dbg_handler.setFormatter(logging.Formatter('%(message)s'))
                root.addHandler(dbg_handler)
            except Exception:
                pass

        # Parity with basicConfig (noop if handlers already exist)
        logging.basicConfig(
            level=root_level,
            format='%(asctime)s %(levelname)s %(message)s'
        )
        return root

# ============================ End Logging / Debug Config =============================


# ================================================================
# Protocol framing layer (MAGIC + PAYLOAD + PADDING)
# ================================================================
class BaseFrame:
    """
    Owns the on-wire frame layout:
    [ MAGIC (20) \
    + PAYLOAD (...) \
    + PADDING ... ] -> 1158 bytes total.
    Changing MAGIC, header size, or padding policy should be done here only.
    """
    MAGIC = bytes.fromhex("C8 00 00 00 02 08 01 02 03 04 05 06 07 05 63 5F 63 69 64 00")
    HEADER_PREFIX_LEN = 20 # MAGIC(20)
    MAX_FRAME_SIZE = 1158 # fixed v1.4 size (CRC removed but length preserved)
    @classmethod
    def max_payload_len(cls) -> int:
        return cls.MAX_FRAME_SIZE - cls.HEADER_PREFIX_LEN
    @classmethod
    def build_envelope(cls, payload_bytes: bytes) -> bytes:
        """Build a fixed-length envelope around an already-formed payload."""
        if len(payload_bytes) > cls.max_payload_len():
            raise ValueError("payload too large for overlay frame")
        unpadded = cls.MAGIC + payload_bytes
        if len(unpadded) < cls.MAX_FRAME_SIZE:
            return unpadded + bytes(cls.MAX_FRAME_SIZE - len(unpadded))
        return unpadded
    @classmethod
    def parse_envelope(cls, dat: bytes) -> Optional[memoryview]:
        if not isinstance(dat, (bytes, bytearray, memoryview)):
            return None
        mv = memoryview(dat)
        if mv.nbytes != cls.MAX_FRAME_SIZE:
            return None
        if mv[:20].tobytes() != cls.MAGIC:
            return None
        # Slice off the full 20-byte prefix (20 MAGIC) to expose inner [ptype][len][payload]
        return mv[cls.HEADER_PREFIX_LEN:]
    @classmethod
    def try_parse_header(cls, dat: bytes):
        """
        Return payload_view or None if dat is not a valid frame envelope.
        Does NOT fully parse payload, only checks framing.
        """
        return cls.parse_envelope(dat)
# ------------------------------------------------------------------
# BaseFrameV2: no MAGIC, no padding
# Header: no HEADER
# ------------------------------------------------------------------
class BaseFrameV2:
    MAGIC = b""
    HEADER_PREFIX_LEN = 0 # no header at all
    MAX_FRAME_SIZE = 1500 - 48 # assume MTU 1500 and deduct IPv6 header 40 + UDP header 8, IPV4 header is 20
    @classmethod
    def max_payload_len(cls) -> int:
        # keep the conservative MTU-based guidance
        return cls.MAX_FRAME_SIZE - cls.HEADER_PREFIX_LEN
    @classmethod
    def build_envelope(cls, payload_bytes: bytes) -> bytes:
        # No length header here; envelope is a pass-through.
        if len(payload_bytes) > cls.max_payload_len():
            raise ValueError("payload too large for frame")
        return payload_bytes
    @classmethod
    def parse_envelope(cls, dat: bytes):
        # Accept any datagram as the envelope; Protocol will validate inner length/PTYPE.
        if not isinstance(dat, (bytes, bytearray, memoryview)):
            return None
        mv = memoryview(dat)
        if mv.nbytes < 1: # must have at least [ptype] in Protocol’s view
            return None
        return mv # no slicing; Protocol will parse length/ptype
# ================================================================
# Protocol layer
# ================================================================
# ================================================================
# Payload layouts (Data / Control) — independent of framing
# ================================================================
# IDLE frames now carry an empty inner payload; DATA/CONTROL payloads no longer include timestamps.
# Protocol header now includes: ptype(1) + len(2) + tx_time_ns(8) + echo_time_ns(8) = 19 bytes.
DATA_PAYLOAD_FIXED = 2 + 1 + 2 + 2 # ctr(2) + type(1) + len_or_off(2) + chunk_len(2)
CONTROL_FIXED_BASE = 2 + 2 + 2 # last(2) + highest(2) + num_missed(2)
# -------------------- Timers / RTT / Keepalive --------------------
RETRANSMIT_UNCONFIRMED_MS = 25
RTT_EWMA_ALPHA = 0.125
RETRANS_MULTIPLIER = 1.5
IDLE_AFTER_MS = 2000
IDLE_CHECK_MS = 200
class Protocol:
    """
    Framing at the Protocol layer with a per-frame inner header:
    [ ptype:1
      len:2
      tx_time_ns:8
      echo_time_ns:8
      payload... ]
    - tx_time_ns: stamped at send.
    - echo_time_ns: last_rx_tx_time_ns + (now - last_rx_wall_ns) at send (or 0 if unknown).
    - On reception, RTT sample = now - echo_time_ns (if echo!=0).
    PTYPEs:
    0 -> IDLE (empty payload)
    1 -> DATA (DataPacket payload)
    2 -> CONTROL (ControlPacket payload)
    """
    PTYPE_IDLE: int = 0x00
    PTYPE_DATA: int = 0x01
    PTYPE_CONTROL: int = 0x02
    def __init__(self, frame_cls: type[BaseFrame]):
        self.frame = frame_cls
        # --- runtime state (RTT/idle/connection) ---
        self.rtt_est_ms: float = 0.0
        self.rtt_sample_ms: float = 0.0
        self.last_rtt_ok_ns: int = 0
        self.last_send_ns: int = 0
        self._last_rx_tx_ns: int = 0
        self._last_rx_wall_ns: int = 0
        self.idle_after_ns: int = int(IDLE_AFTER_MS * 1e6)
        self.connected_loss_ns: int = int(20 * 1e9) # 20 s without RTT success = disconnected
    @property
    def MAGIC(self):
        return self.frame.MAGIC
    @property
    def MAX_FRAME_SIZE(self):
        return self.frame.MAX_FRAME_SIZE
    def max_payload_len(self) -> int:
        # Reserve protocol header (ptype+len+tx+echo == 1+2+8+8 == 19) inside the envelope.
        base = self.frame.max_payload_len()
        return max(0, base - 19)
    # -------- build/parse (with times) --------
    def build_frame(self, ptype: int, payload: bytes, initial=False) -> bytes:
        if not (0 <= ptype <= 255):
            raise ValueError("ptype out of range")
        if len(payload) > self.max_payload_len():
            raise ValueError("payload too large for overlay frame")
        # Stamp tx/echo
        tx_ns = now_ns()
        echo_ns = 0
        if self._last_rx_tx_ns and self._last_rx_wall_ns and not initial:
            echo_ns = self._last_rx_tx_ns + (tx_ns - self._last_rx_wall_ns)
        inner = (
            bytes([ptype]) +
            struct.pack(">H", len(payload)) +
            struct.pack(">Q", tx_ns) +
            struct.pack(">Q", echo_ns) +
            payload
        )
        frame = self.frame.build_envelope(inner)
        self.on_data_sent(tx_ns)
        return frame
    def parse_frame_with_times(
        self, dat: bytes
    ) -> Optional[Tuple[int, memoryview, int, int]]:
        """New parser returning (ptype, payload, tx_ns, echo_ns)."""
        env = self.frame.parse_envelope(dat)
        if env is None or env.nbytes < 19:
            return None
        ptype = int(env[0])
        plen = struct.unpack(">H", env[1:3])[0]
        tx_ns = struct.unpack(">Q", env[3:11])[0]
        echo_ns = struct.unpack(">Q", env[11:19])[0]
        start = 19
        if env.nbytes < start + plen:
            return None
        return ptype, env[start:start+plen], tx_ns, echo_ns
    # -------- runtime helpers (RTT/idle/conn) --------
    def on_frame_received(self, tx_ns: int, recv_wall_ns: int) -> None:
        # Save info to compute echo for our next send
        self._last_rx_wall_ns = recv_wall_ns
        self._last_rx_tx_ns = tx_ns
    def on_control_echo(self, echo_tx_ns: int) -> None:
        if echo_tx_ns == 0:
            return
        sample = (now_ns() - echo_tx_ns) / 1e6 # ms
        self.rtt_sample_ms = sample
        self.last_rtt_ok_ns = now_ns()
        if self.rtt_est_ms < sample:
            self.rtt_est_ms = sample
        else:
            self.rtt_est_ms = (1 - RTT_EWMA_ALPHA) * self.rtt_est_ms + RTT_EWMA_ALPHA * sample
    def is_connected(self, now_ns_val: Optional[int] = None) -> bool:
        if self.last_rtt_ok_ns == 0:
            return False
        now_v = now_ns_val or now_ns()
        return (now_v - self.last_rtt_ok_ns) <= self.connected_loss_ns
    def on_data_sent(self, tx_ns: Optional[int] = None) -> None:
        # Only used to track TX timestamp, no idle behavior depends on this anymore
        self.last_send_ns = tx_ns if tx_ns is not None else now_ns()
    def build_idle_ping(self, initial) -> bytes:
        """Empty payload IDLE frame: PTYPE=0, PLEN=0."""
        return self.build_frame(self.PTYPE_IDLE, b"", initial)
# --- protocol-layer runtime (per PeerProtocol instance) ---
class ProtocolRuntime:
    """
    Connectivity + RTT-staleness idle logic.
    New behavior:
    - When not connected: send initial idle probe periodically
    - When connected: send idle only when (now - last_rtt_ok >= 2s)
    - Repeat every 2s until RTT succeeds again
    - No idle-after-send logic
    - No idle reflections
    """
    def __init__(self, proto: Protocol, log: Optional[logging.Logger] = None):
        self.proto = proto
        self._log = (log or logging.getLogger(__name__)).getChild("rt")
        self._send_fn = None
        self._on_state_change = None
        self._tick_task = None
        self._conn_evt = asyncio.Event()
        self._conn_state = False
        self._probe_interval_s = 1.0 # for disconnected probing
        self._idle_check_s = 0.2 # polling granularity
        self._rtt_timeout_ns = 2_000_000_000 # 2s
        self._next_probe_due_ns = 0 # <-- NEW: absolute deadline
    def attach(self, send_fn, on_state_change=None):
        self._log.debug(f"[Attach] on_state_change_fnct {on_state_change}")
        self._send_fn = send_fn
        # wrap state change to also log transitions

        if on_state_change:
            def _wrapped_cb(state: bool, _cb=on_state_change):
                self._log.debug(f"[STATE] {'CONNECTED' if state else 'DISCONNECTED'}")
                try:
                    _cb(state)
                except Exception as e:
                    self._log.debug(f"[STATE] cb failed %r",e)
                    pass
            self._on_state_change = _wrapped_cb
        else:
            def _wrapped_no_cb(state: bool, _cb=on_state_change):
                self._log.debug(f"[STATE] {'CONNECTED' if state else 'DISCONNECTED'}")
            self._on_state_change = _wrapped_no_cb
        if self._tick_task is None:
            loop = asyncio.get_running_loop()
            self._tick_task = loop.create_task(self._tick())
    def detach(self):
        if self._tick_task:
            self._tick_task.cancel()
            self._tick_task = None
        self._send_fn = None
        self._on_state_change = None
        self._conn_evt.clear()
        self._conn_state = False
    async def wait_connected(self, timeout=None):
        if self.proto.is_connected():
            return True
        try:
            await asyncio.wait_for(self._conn_evt.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _send_idle_probe(self, initial=True):
        if not self._send_fn:
            self._log.debug(f"[IDLE]no send function attached")
            return
        try:
            frame = self.proto.build_idle_ping(initial)
            self._log.debug(f"[IDLE] tx initial={initial}")
            self._log.debug(
                "[IDLE/TX] initial=%s proto_connected=%s last_rtt_ok_ns=%d last_rx_tx_ns=%d",
                initial,
                self.proto.is_connected(),
                getattr(self.proto, "last_rtt_ok_ns", 0),
                getattr(self.proto, "_last_rx_tx_ns", 0),
            )
            self._send_fn(frame)
        except Exception as e:
            self._log.debug(f"[IDLE] _send_idle_probe failed on self._send_fn %r",e)

    async def _tick(self):
        try:
            while True:
                connected_now = self.proto.is_connected()
                # state transitions
                if connected_now != self._conn_state:
                    self._conn_state = connected_now
                    if connected_now:
                        # Anchor next probe to last RTT OK + 2s
                        last_ok = self.proto.last_rtt_ok_ns
                        base = last_ok if last_ok != 0 else now_ns()
                        self._next_probe_due_ns = base + self._rtt_timeout_ns
                        self._conn_evt.set()
                    else:
                        self._conn_evt.clear()
                        self._next_probe_due_ns = 0
                    if callable(self._on_state_change):
                        try:
                            self._on_state_change(connected_now)
                        except Exception:
                            pass
                if not connected_now:
                    # disconnected: periodic initial probes
                    self._send_idle_probe(initial=True)
                    await asyncio.sleep(self._probe_interval_s)
                    continue
                # connected: deadline-based probing
                now = now_ns()
                last_ok = self.proto.last_rtt_ok_ns
                # If RTT refreshed, move the deadline forward
                if last_ok != 0:
                    # Keep deadline aligned to the freshest RTT OK
                    self._next_probe_due_ns = max(self._next_probe_due_ns, last_ok + self._rtt_timeout_ns)
                # If we’re past the deadline, send one probe and push by 2s
                if self._next_probe_due_ns and now >= self._next_probe_due_ns:
                    self._send_idle_probe(initial=True)
                    self._next_probe_due_ns = now + self._rtt_timeout_ns
                await asyncio.sleep(self._idle_check_s)
        except asyncio.CancelledError:
            return
# Single global protocol instance (keeps public API the same for runner/tests)
PROTO = Protocol(BaseFrameV2)
#PROTO = Protocol(BaseFrame)
# Exported compatibility constants (kept identical to old API)
MAGIC = PROTO.MAGIC
PTYPE_DATA = PROTO.PTYPE_DATA
PTYPE_CONTROL = PROTO.PTYPE_CONTROL
UDP_FRAME_SIZE = PROTO.MAX_FRAME_SIZE
# same numeric result as legacy: (1158-21)-22 -> space for missed list
# For reference/compat with old math: DATA header including frame-prefix == 21 + 15 = 36
DATA_UNPADDED_HEADER_SIZE = BaseFrame.HEADER_PREFIX_LEN + DATA_PAYLOAD_FIXED
# Keep derived sizes consistent with Protocol header.
CONTROL_MAX_MISSED = (PROTO.max_payload_len() - CONTROL_FIXED_BASE) // 2
DATA_MAX_CHUNK = PROTO.max_payload_len() - DATA_PAYLOAD_FIXED
# -------------------- Utility helpers --------------------
def now_ns() -> int:
    return time.monotonic_ns()

def ring_cmp(a: int, b: int) -> int:
    if a == b:
        return 0
    ar = a - 1
    br = b - 1
    d = (ar - br) % 65535
    if d >= 32768:
        d -= 65535
    return d

def c16_inc(c: int) -> int:
    return 1 if c == 65535 else c + 1

def c16_dec(c: int) -> int:
    return 65535 if c == 1 else c - 1

def c16_range(start_inclusive: int, end_exclusive: int) -> List[int]:
    res: List[int] = []
    c = start_inclusive
    while c != end_exclusive:
        res.append(c)
        c = c16_inc(c)
    return res

def highest_ring(keys: List[int], ref: int) -> Optional[int]:
    if not keys:
        return None
    def order_key(a: int) -> int:
        ar = a - 1
        br = ref - 1
        return (ar - br) % 65535
    return max(keys, key=order_key)

def ahead_distance(a: int, ref: int) -> int:
    ar = a - 1
    br = ref - 1
    return (ar - br) % 65535
# -------------------- Frames: DataPacket --------------------
class DataPacket:
    __slots__ = ("pkt_counter", "frame_type", "len_or_offset", "chunk_len", "data", "raw")
    def __init__(self, pkt_counter: int, frame_type: int, len_or_offset: int,
                 chunk_len: int, data: bytes, raw: bytes):
        self.pkt_counter = pkt_counter
        self.frame_type = frame_type
        self.len_or_offset = len_or_offset
        self.chunk_len = chunk_len
        self.data = data
        self.raw = raw # full frame bytes
    # -------- payload API (timestamps are NOT part of payload anymore) --------
    @staticmethod
    def build_payload(pkt_counter: int, frame_type: int,
                      len_or_offset: int, data: bytes, * _ignored_tx_ns) -> bytes:
        """
        Signature kept backward-compatible (tx_ns is ignored).
        """
        is_idle = (pkt_counter == 0 and frame_type == FRAME_FIRST and len(data) == 0)
        if not is_idle and not (1 <= pkt_counter <= 65535):
            raise ValueError("pkt_counter out of range")
        chunk_len = len(data)
        if chunk_len == 0 and frame_type != FRAME_FIRST:
            raise ValueError("zero-length chunk only valid for FRAME_FIRST")
        if chunk_len > DATA_MAX_CHUNK:
            raise ValueError("chunk too large")
        if not (0 <= len_or_offset <= 65535):
            raise ValueError("len_or_offset out of range")
        return (
            struct.pack(">H", pkt_counter) +
            bytes([frame_type]) +
            struct.pack(">H", len_or_offset) +
            struct.pack(">H", chunk_len) +
            data
        )
    @staticmethod
    def parse_payload(payload: memoryview, full_raw: bytes) -> Optional["DataPacket"]:
        if payload.nbytes < DATA_PAYLOAD_FIXED:
            return None
        try:
            pkt_counter = struct.unpack(">H", payload[0:2])[0]
            frame_type = int(payload[2])
            len_or_offset = struct.unpack(">H", payload[3:5])[0]
            chunk_len = struct.unpack(">H", payload[5:7])[0]
            if 7 + chunk_len > payload.nbytes:
                return None
            data = payload[7:7 + chunk_len].tobytes()
            return DataPacket(pkt_counter, frame_type, len_or_offset, chunk_len, data, full_raw)
        except Exception:
            return None
    # -------- convenience wrappers --------
    @staticmethod
    def build_full(pkt_counter: int, frame_type: int, len_or_offset: int,
                   data: bytes) -> "DataPacket":
        payload = DataPacket.build_payload(pkt_counter, frame_type, len_or_offset, data)
        frame = PROTO.build_frame(PTYPE_DATA, payload)
        return DataPacket.parse_full(frame) # type: ignore
    @staticmethod
    def parse_full(dat: bytes) -> Optional["DataPacket"]:
        parsed = PROTO.parse_frame_with_times(dat)
        if not parsed:
            return None
        ptype, payload, _tx_ns, _echo_ns = parsed
        if ptype != PTYPE_DATA:
            return None
        return DataPacket.parse_payload(payload, dat)
# -------------------- Frames: ControlPacket --------------------
class ControlPacket:
    __slots__ = ("last_in_order_rx", "highest_rx", "missed", "raw")
    def __init__(self, last_in_order_rx: int, highest_rx: int, missed: List[int], raw: bytes):
        self.last_in_order_rx = last_in_order_rx
        self.highest_rx = highest_rx
        self.missed = missed
        self.raw = raw
    @staticmethod
    def build_payload(last_in_order_rx: int, highest_rx: int,
                      missed: List[int], * _ignored_times) -> bytes:
        """
        Signature kept backward-compatible (ctl_ns/echo_ns args ignored).
        """
        if not (0 <= last_in_order_rx <= 65535):
            raise ValueError("last_in_order_rx out of range")
        if not (0 <= highest_rx <= 65535):
            raise ValueError("highest_rx out of range")
        missed = list(missed)[:CONTROL_MAX_MISSED]
        return (
            struct.pack(">H", last_in_order_rx) +
            struct.pack(">H", highest_rx) +
            struct.pack(">H", len(missed)) +
            b"".join(struct.pack(">H", m) for m in missed)
        )
    @staticmethod
    def parse_payload(payload: memoryview, full_raw: bytes) -> Optional["ControlPacket"]:
        if payload.nbytes < CONTROL_FIXED_BASE:
            return None
        try:
            last_in_order_rx = struct.unpack(">H", payload[0:2])[0]
            highest_rx = struct.unpack(">H", payload[2:4])[0]
            num_missed = struct.unpack(">H", payload[4:6])[0]
            miss_end = 6 + 2 * num_missed
            if miss_end > payload.nbytes:
                return None
            missed = [struct.unpack(">H", payload[6+2*i:6+2*(i+1)])[0] for i in range(num_missed)]
            return ControlPacket(last_in_order_rx, highest_rx, missed, full_raw)
        except Exception:
            return None
    @staticmethod
    def build_full(last_in_order_rx: int, highest_rx: int,
                   missed: List[int]) -> "ControlPacket":
        payload = ControlPacket.build_payload(last_in_order_rx, highest_rx, missed)
        frame = PROTO.build_frame(PTYPE_CONTROL, payload)
        return ControlPacket.parse_full(frame) # type: ignore
    @staticmethod
    def parse_full(dat: bytes) -> Optional["ControlPacket"]:
        parsed = PROTO.parse_frame_with_times(dat)
        if not parsed:
            return None
        ptype, payload, _tx_ns, _echo_ns = parsed
        if ptype != PTYPE_CONTROL:
            return None
        return ControlPacket.parse_payload(payload, dat)
# -------------------- Reassembly --------------------
class Reassembly:
    __slots__ = ("total_len", "buf", "marks", "filled", "start_ns")
    def __init__(self, total_len: int):
        self.total_len = total_len
        self.buf = bytearray(total_len)
        self.marks = bytearray(total_len)
        self.filled = 0
        self.start_ns = now_ns()
    def apply(self, offset: int, data: bytes) -> None:
        end = offset + len(data)
        if offset < 0 or end > self.total_len:
            return
        self.buf[offset:end] = data
        new = 0
        for i in range(offset, end):
            if self.marks[i] == 0:
                self.marks[i] = 1
                new += 1
        self.filled += new
    def complete(self) -> bool:
        return self.filled >= self.total_len
# -------------------- SendPort --------------------
class SendPort:
    """
    Model B only:
    - The overlay UDP socket is always unconnected at the OS level.
    - Current destination is owned by SendPort.peer_addr.
    - --peer is only an initial seed; peer may later be relearned/moved.
    - Do not reintroduce connected-UDP behavior here unless the protocol-level
      peer learning/relearning logic is removed as well.
    """

    def __init__(
        self,
        udp_transport: asyncio.DatagramTransport,
        log: logging.Logger,
        initial_peer: Optional[Tuple[str, int]] = None,
        on_bytes_sent: Optional[Callable[[int], None]] = None,
    ):
        self.udp_transport = udp_transport
        self.log = log
        self.peer_addr: Optional[Tuple[str, int]] = initial_peer
        self._on_bytes_sent = on_bytes_sent

    @staticmethod
    def _pretty(addr) -> str:
        try:
            if isinstance(addr, tuple) and len(addr) >= 2:
                host, port = str(addr[0]), int(addr[1])
                return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
            return str(addr)
        except Exception:
            return "?"

    def set_peer(self, addr: Optional[Tuple[str, int]]) -> None:
        if self.peer_addr != addr:
            self.log.info("Overlay peer learned: %s", SendPort._pretty(addr))
            self.peer_addr = addr

    def clear_peer(self) -> None:
        if self.peer_addr is not None:
            self.log.info("Overlay peer cleared: %s", SendPort._pretty(self.peer_addr))
            self.peer_addr = None

    def sendto(self, data: bytes) -> None:
        if not data:
            return

        src = self.udp_transport.get_extra_info("sockname") if self.udp_transport else None
        dst = self.peer_addr

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(
                "[SENDPORT] send peer_addr=%r len=%d",
                dst,
                len(data),
            )

        if dst is None:
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug("[PEER/TX] drop %dB: no learned peer yet", len(data))
            return

        try:
            self.udp_transport.sendto(data, dst)
            if self._on_bytes_sent:
                self._on_bytes_sent(len(data))
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(
                    "[PEER/TX] %dB -> %s -> %s",
                    len(data),
                    SendPort._pretty(src),
                    SendPort._pretty(dst),
                )
        except Exception as e:
            self.log.error("[PEER/TX] send failed: %r", e)
            raise            
# -------------------- Session --------------------
OutgoingSegment = Tuple[int, int, bytes]
class Session:
    def __init__(self, max_in_flight: int = 32767, proto: Optional[Protocol] = None):
        self.proto = proto or PROTO
        self.next_ctr = 1
        self.send_buf: Dict[int, bytes] = {}
        self.send_meta: Dict[int, OutgoingSegment] = {}
        self.send_txns: Dict[int, int] = {}
        self.last_retx_ns: Dict[int, int] = {}
        self.send_attempts: Dict[int, int] = {}
        self.data_pkt_flags: Dict[int, bool] = {}
        self.stats_hist = {
            "once": 0, "twice": 0, "thrice": 0, "gt3": 0,
            "confirmed_total": 0, "created_total": 0,
        }
        self.max_in_flight = max(1, min(32767, int(max_in_flight)))
        self.wait_queue: Deque[OutgoingSegment] = deque()
        self.expected = 1
        self.pending: Dict[int, DataPacket] = {}
        self.missing: Set[int] = set()
        self.reass: Optional[Reassembly] = None
        # RTT mirrors read from Protocol (source of truth)
        self.last_sent_ctr = 0
        self.last_ack_peer = 0
        self.peer_missed_count = 0
        self.last_send_ns = 0
        self.log = logging.getLogger("udp_session")
        # Track which counters contributed to current reassembly (for logging)
        self._reass_ctrs: Set[int] = set()
        # internal marker for emission trigger text
        self._last_emit_trigger: str = "app_send"
    # ---------- helpers formerly free-standing ----------
    @staticmethod
    def last_in_order_from_expected(expected: int) -> int:
        return 0 if expected == 1 else c16_dec(expected)
    def last_in_order(self) -> int:
        return Session.last_in_order_from_expected(self.expected)
    def _compute_highest_rx(self) -> int:
        last_in_order = self.last_in_order()
        candidates: List[int] = []
        if last_in_order != 0:
            candidates.append(last_in_order)
        candidates.extend([k for k in self.pending.keys() if k != 0])
        if not candidates:
            return 0
        hi = highest_ring(candidates, last_in_order if last_in_order != 0 else 1)
        return hi if hi is not None else 0
    @staticmethod
    def _sort_missed_for_control(missed: Set[int], ref: int) -> List[int]:
        if not missed:
            return []
        missed = {m for m in missed if m != 0}
        if not missed:
            return []
        ordered = sorted(missed, key=lambda x: ring_cmp(x, ref))
        return ordered[:CONTROL_MAX_MISSED]
    def build_control(self) -> ControlPacket:
        last_in_order = self.last_in_order()
        highest_rx = self._compute_highest_rx()
        if highest_rx == 0:
            filtered_missed: List[int] = []
        else:
            filtered_missed = [m for m in self.missing if m != 0 and ring_cmp(highest_rx, m) >= 0]
        missed_sorted = Session._sort_missed_for_control(set(filtered_missed), last_in_order)
        payload = ControlPacket.build_payload(last_in_order, highest_rx, missed_sorted)
        frame = self.proto.build_frame(PTYPE_CONTROL, payload)
        cp = ControlPacket.parse_full(frame)
        assert cp is not None
        return cp
    # ------------- send path -------------
    def reserve_ctr(self) -> int:
        c = self.next_ctr
        self.next_ctr = c16_inc(c)
        return c
    def in_flight(self) -> int:
        return len(self.send_buf)
    def waiting_count(self) -> int:
        return len(self.wait_queue)
    def _record_created_if_appdata(self, ctr: int, chunk: bytes) -> None:
        is_app = len(chunk) > 0
        self.data_pkt_flags[ctr] = is_app
        if is_app:
            self.stats_hist["created_total"] += 1
    def _bump_attempt(self, ctr: int) -> None:
        if ctr == 0:
            return
        self.send_attempts[ctr] = self.send_attempts.get(ctr, 0) + 1
    def _emit_now(self, seg: OutgoingSegment, transport: Any) -> None:
        frame_type, off_or_len, chunk = seg
        ctr = self.reserve_ctr()
        tx = now_ns()
        self._record_created_if_appdata(ctr, chunk)
        try:
            payload = DataPacket.build_payload(ctr, frame_type, off_or_len, chunk, tx)
            frame = self.proto.build_frame(PTYPE_DATA, payload)
            transport.sendto(frame)
        except Exception:
            self.wait_queue.appendleft(seg)
            return
        self.send_meta[ctr] = (frame_type, off_or_len, chunk)
        self.send_buf[ctr] = frame
        self.send_txns[ctr] = tx
        self.last_sent_ctr = ctr
        self.last_send_ns = tx
        self._bump_attempt(ctr)
        if self.log.isEnabledFor(logging.DEBUG):
            trig = getattr(self, "_last_emit_trigger", "app_send")
            self.log.debug(f"[TX] DATA ctr={ctr} trig={trig} type={frame_type} off/len={off_or_len} chunk_len={len(chunk)} inflight={len(self.send_buf)} queued={len(self.wait_queue)}")
    def try_flush_send_queue(self, transport: Any) -> int:
        emitted = 0
        while self.in_flight() < self.max_in_flight and self.wait_queue:
            seg = self.wait_queue.popleft()
            self._last_emit_trigger = "flush_queue"
            self._emit_now(seg, transport)
            emitted += 1
        self._last_emit_trigger = "app_send"
        return emitted
    def _send_or_queue(self, seg: OutgoingSegment, transport: Any) -> None:
        if self.in_flight() < self.max_in_flight:
            self._last_emit_trigger = "app_send"
            self._emit_now(seg, transport)
        else:
            self.wait_queue.append(seg)
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(f"[TX] QUEUE type={seg[0]} off/len={seg[1]} chunk_len={len(seg[2])} inflight={len(self.send_buf)} queued={len(self.wait_queue)}")
    def _finalize_stats_for(self, cnt: int) -> None:
        if not self.data_pkt_flags.pop(cnt, False):
            self.send_attempts.pop(cnt, None)
            return
        attempts = self.send_attempts.pop(cnt, 1)
        self.stats_hist["confirmed_total"] += 1
        if attempts == 1:
            self.stats_hist["once"] += 1
        elif attempts == 2:
            self.stats_hist["twice"] += 1
        elif attempts == 3:
            self.stats_hist["thrice"] += 1
        else:
            self.stats_hist["gt3"] += 1
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(f"[ACK] confirmed ctr={cnt} attempts={attempts}")
    # ------------- ACK/feedback (no timers/retrans scheduling here) -------------
    def confirm_with_feedback(self, last_in_order: int, highest: int, missed: List[int]) -> None:
        if last_in_order == 0 and highest == 0 and len(missed) == 0:
            return
        missed_set = set(missed)
        full_list = len(missed) >= CONTROL_MAX_MISSED
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(f"[CTL<-] LIO={last_in_order} HI={highest} missed_count={len(missed)} full_list={full_list}")
        # delete <= last_in_order
        to_del = [cnt for cnt in list(self.send_buf.keys())
                  if ring_cmp(last_in_order, cnt) >= 0]
        for cnt in to_del:
            self._finalize_stats_for(cnt)
            self.send_buf.pop(cnt, None)
            self.send_txns.pop(cnt, None)
            self.last_retx_ns.pop(cnt, None)
            self.send_meta.pop(cnt, None)
        if self.log.isEnabledFor(logging.DEBUG) and to_del:
            self.log.debug(f"[ACK] drop <= LIO: {to_del[:20]}{'…' if len(to_del)>20 else ''}")
        ref = last_in_order if last_in_order != 0 else 1
        if full_list and missed:
            max_missed = highest_ring(missed, ref)
            upper_bound = max_missed if max_missed is not None else last_in_order
        else:
            upper_bound = highest
        max_span = ahead_distance(upper_bound, ref)
        def in_range(x: int) -> bool:
            d = ahead_distance(x, ref)
            return 0 < d <= max_span
        to_del2 = [cnt for cnt in list(self.send_buf.keys())
                   if in_range(cnt) and cnt not in missed_set]
        for cnt in to_del2:
            self._finalize_stats_for(cnt)
            self.send_buf.pop(cnt, None)
            self.send_txns.pop(cnt, None)
            self.last_retx_ns.pop(cnt, None)
            self.send_meta.pop(cnt, None)
        if self.log.isEnabledFor(logging.DEBUG) and to_del2:
            self.log.debug(f"[ACK] drop within span(non-missed): {to_del2[:20]}{'…' if len(to_del2)>20 else ''}")
        self.last_ack_peer = last_in_order
    # ------------- RTT mirrors -------------
    @property
    def rtt_est_ms(self) -> float:
        return self.proto.rtt_est_ms
    @property
    def rtt_sample_ms(self) -> float:
        return self.proto.rtt_sample_ms
    @property
    def last_rtt_ok_ns(self) -> int:
        return self.proto.last_rtt_ok_ns
    def update_rtt(self, echo_tx_ns: int) -> None:
        before = (self.proto.rtt_sample_ms, self.proto.rtt_est_ms)
        self.proto.on_control_echo(echo_tx_ns)
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(f"[RTT] sample_ms={self.proto.rtt_sample_ms:.3f} est_ms={self.proto.rtt_est_ms:.3f} (prev {before[0]:.3f}/{before[1]:.3f})")
    # ------------- RX side (DATA) -------------
    def identify_missing(self):
        pendingkeylist = [k for k in self.pending.keys() if k != 0]
        self.missing.clear()
        if pendingkeylist:
            hi = highest_ring(pendingkeylist, self.expected)
            if hi is not None:
                for m in c16_range(self.expected, hi):
                    if m not in self.pending:
                        self.missing.add(m)
        if self.log.isEnabledFor(logging.DEBUG):
            try:
                pend = sorted(self.pending.keys())[:12]
                miss = sorted(self.missing)[:12]
                self.log.debug(f"[RX] pending={pend}{'…' if len(self.pending)>12 else ''} missing={miss}{'…' if len(self.missing)>12 else ''} expected={self.expected}")
            except Exception:
                pass
    def process_data(self, pkt: DataPacket) -> Tuple[bool, List[bytes]]:
        if pkt.pkt_counter == 0:
            return False, []
        adv = False
        completed: List[bytes] = []
        X = pkt.pkt_counter
        cmpv = ring_cmp(X, self.expected)
        if cmpv < 0:
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(f"[RX] ctr={X} DROP (old) expected={self.expected}")
            return adv, completed
        elif cmpv == 0:
            adv = True
            self.expected = c16_inc(self.expected)
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(f"[RX] ctr={X} IN-ORDER -> advance expected={self.expected}")
        else:
            self.pending[X] = pkt
            self.identify_missing()
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(f"[RX] ctr={X} QUEUED (gap); frame_type={pkt.frame_type} off/len={pkt.len_or_offset} chunk_len={pkt.chunk_len}")
            return adv, completed
        if pkt.frame_type == FRAME_FIRST:
            if self.reass is None:
                total = pkt.len_or_offset
                if 0 < total <= 65535:
                    self.reass = Reassembly(total)
                    self._reass_ctrs = set()
            if self.reass is not None:
                self.reass.apply(0, pkt.data)
                self._reass_ctrs.add(X)
        else:
            if self.reass is not None:
                self.reass.apply(pkt.len_or_offset, pkt.data)
                self._reass_ctrs.add(X)
        if self.reass is not None and self.reass.complete():
            completed.append(bytes(self.reass.buf))
            if self.log.isEnabledFor(logging.DEBUG):
                try:
                    used = sorted(self._reass_ctrs)
                    self.log.debug(f"[APP] completed len={len(completed[-1])} using_ctrs={used}")
                except Exception:
                    pass
            self.reass = None
            self._reass_ctrs = set()
        if adv:
            while True:
                nxt = self.expected
                p = self.pending.pop(nxt, None)
                if p is None:
                    break
                self.missing.discard(nxt)
                self.expected = c16_inc(self.expected)
                if self.log.isEnabledFor(logging.DEBUG):
                    self.log.debug(f"[RX] ctr={nxt} POP from pending -> advance expected={self.expected}")
                if p.frame_type == FRAME_FIRST:
                    if self.reass is None:
                        total = p.len_or_offset
                        if 0 < total <= 65535:
                            self.reass = Reassembly(total)
                            self._reass_ctrs = set()
                    if self.reass is not None:
                        self.reass.apply(0, p.data)
                        self._reass_ctrs.add(nxt)
                else:
                    if self.reass is not None:
                        self.reass.apply(p.len_or_offset, p.data)
                        self._reass_ctrs.add(nxt)
                if self.reass is not None and self.reass.complete():
                    completed.append(bytes(self.reass.buf))
                    if self.log.isEnabledFor(logging.DEBUG):
                        try:
                            used = sorted(self._reass_ctrs)
                            self.log.debug(f"[APP] completed len={len(completed[-1])} using_ctrs={used}")
                        except Exception:
                            pass
                    self.reass = None
                    self._reass_ctrs = set()
            self.identify_missing()
        return adv, completed
    # ------------- API -------------
    def send_application_payload(self, data: bytes, transport: Any) -> int:
        if not data or transport is None:
            return 0
        total = len(data)
        if total <= 0 or total > 65535:
            return 0
        produced = 0
        first_chunk = data[:DATA_MAX_CHUNK]
        first_seg = (FRAME_FIRST, total, first_chunk)
        self._send_or_queue(first_seg, transport)
        produced += 1
        off = len(first_chunk)
        while off < total:
            chunk = data[off: off + DATA_MAX_CHUNK]
            seg = (FRAME_CONT, off, chunk)
            self._send_or_queue(seg, transport)
            produced += 1
            off += len(chunk)
        self.try_flush_send_queue(transport)
        return produced
    def reset_sender(self) -> None:
        self.send_buf.clear()
        self.send_meta.clear()
        self.send_txns.clear()
        self.last_retx_ns.clear()
        self.wait_queue.clear()
        self.send_attempts.clear()
        self.data_pkt_flags.clear()
        self.next_ctr = 1
        self.expected = 1
        self.pending.clear()
        self.missing.clear()
        self.reass = None
        self.last_sent_ctr = 0
        self.last_ack_peer = 0
        self.peer_missed_count = 0
        self.last_send_ns = 0
# -------------------- PeerProtocol --------------------
FRAME_FIRST = 0x01
FRAME_CONT = 0x02
class PeerProtocol(asyncio.DatagramProtocol):
    """
    CONTROL emission policy (PeerProtocol-owned):
    (a) emit immediately if new missing entries appear on inbound DATA
    (b) emit when in-order advanced and miss-list empty, with pacing
    (c) emit when miss-list non-empty, paced by RTT
    PeerProtocol additionally owns loss detection & mitigation:
    - schedule retransmissions upon CONTROL feedback
    - periodic sweep of unconfirmed for time-based retransmit
    """
    def __init__(
        self,
        session: Session,
        on_control_needed,
        on_complete,
        peer=None,
        proto: Optional[Protocol] = None,
        on_peer_set=None,
        on_peer_rx_bytes: Optional[Callable[[int], None]] = None,
        on_peer_tx_bytes: Optional[Callable[[int], None]] = None,
        on_rtt_success: Optional[Callable[[int], None]] = None,
        on_state_change: Optional[Callable[[bool], None]] = None,
    ):
        self.session = session
        self.proto = proto or getattr(session, "proto", PROTO)
        self.peer = peer
        self.udp_transport: Optional[asyncio.DatagramTransport] = None
        self.send_port: Optional[SendPort] = None
        self.on_control_needed = on_control_needed
        self.on_complete = on_complete
        self.on_peer_set = on_peer_set
        self._on_peer_rx_bytes = on_peer_rx_bytes
        self._on_peer_tx_bytes = on_peer_tx_bytes
        self._on_rtt_success = on_rtt_success
        self._on_state_change = on_state_change
        super().__init__()
        self._last_control_sent_ns = 0
        self._last_sent_last_in_order = 0
        self._established_ns = 0
        self._unidentified_frames = 0
        # Per-peer runtime for connectivity & idle pings (with logger)
        self._proto_rt = ProtocolRuntime(self.proto, log=self.session.log.getChild("rt"))
        self._runtime_attached = False
        self._ctl_task = None
        self._retx_task = None
        self._move_grace_ns = int(3 * 1e9)  # 3 seconds

    @property
    def unidentified_frames(self) -> int:
        return self._unidentified_frames

    def connection_made(self, transport: asyncio.BaseTransport):
        log = self.session.log
        self.udp_transport = transport

        local = None
        peername = None
        try:
            local = transport.get_extra_info("sockname")
            peername = transport.get_extra_info("peername")
        except Exception as e:
            log.debug("[UDP/PROTO] get extra info failed - normal on server %r", e)

        seed_peer = getattr(self.send_port, "peer_addr", None)

        log.debug(
            "[UDP/PROTO] connection_made; local=%r peername=%r seeded_peer=%r",
            local,
            peername,
            seed_peer,
        )

        # Model B:
        # Ignore OS peername as authoritative routing state.
        # Use configured self.peer only as the initial seed.
        forced_peer = None
        if self.peer:
            forced_peer = self.peer
            log.debug("[UDP/PROTO] forced peer assignment %r", forced_peer)
        else:
            log.debug("[UDP/PROTO] no configured peer; waiting to learn peer from first RX")

        self.send_port = SendPort(
            self.udp_transport,
            self.session.log,
            initial_peer=forced_peer,
            on_bytes_sent=self._on_peer_tx_bytes,
        )

        self.controltimerstart()
        self.retxtimerstart()

        log.debug("[UDP/PROTO] send_port initialized with peer=%r", forced_peer)

        self.notify_send_port_ready()

        log.debug("[UDP/PROTO] peer send ready")
        
    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.session.log.debug("[UDP/PROTO] connection_lost exc=%r", exc)
        try:
            self._proto_rt.detach()
        except Exception:
            pass
        self.controltimerstop()
        self.retxtimerstop()

    def error_received(self, exc):
        self.session.log.debug("[UDP/PROTO] error_received exc=%r", exc)


    def notify_send_port_ready(self) -> None:
        self.session.log.debug(
            "[UDP/PROTO] notify_send_port_ready runtime_attached_before=%s send_port=%r",
            self._runtime_attached,
            self.send_port.peer_addr if self.send_port else None,
        )        

        if self.send_port and not self._runtime_attached:
            try:
                self.session.log.debug("[UDP/PROTO] transition runtime not attached -> attached")
                self._proto_rt.attach(self.send_port.sendto, self._on_state_change)
                self._runtime_attached = True
                # NEW: kick one initial probe right away
                self.send_idle_ping(initial=True)
            except Exception as e:
                self._runtime_attached = False
                self.session.log.debug("[UDP/PROTO] notify_send_port_ready failed %r",e )

    def _maybe_learn_peer(self, addr):
        log = self.session.log

        if self.send_port is None:
            log.debug("[UDP/PROTO] _maybe_learn_peer skipped: send_port=None addr=%r", addr)
            return

        host, port = str(addr[0]), int(addr[1])
        full_addr = addr
        cur = self.send_port.peer_addr

        try:
            proto_connected = bool(self.proto.is_connected())
            last_ok = int(self.proto.last_rtt_ok_ns)
        except Exception:
            proto_connected, last_ok = False, 0

        age_s = None
        if last_ok:
            try:
                age_s = (now_ns() - last_ok) / 1e9
            except Exception:
                age_s = None

        log.debug(
            "[PEER/LEARN/CHECK] incoming=%r current=%r proto_connected=%s age_last_rtt=%s grace_s=%.3f",
            full_addr,
            cur,
            proto_connected,
            ("n/a" if age_s is None else f"{age_s:.3f}"),
            self._move_grace_ns / 1e9,
        )

        # 1) First-time learn: adopt immediately
        if cur is None:
            log.info(
                "[PEER/LEARN] action=initial-adopt old=%r new=%r reason=no_current_peer",
                cur,
                full_addr,
            )
            self.send_port.set_peer(full_addr)
            if callable(self.on_peer_set):
                self.on_peer_set(host, port)
            return

        # 1b) Same peer -> nothing to do
        if cur and (host, port) == cur:
            log.debug(
                "[PEER/LEARN] action=keep old=%r new=%r reason=same_peer",
                cur,
                full_addr,
            )
            return

        # 2) Peer move: source changed
        if cur and (host, port) != cur:
            adopt = (not proto_connected) or (now_ns() - (last_ok or 0) >= self._move_grace_ns)

            if adopt:
                log.info(
                    "[PEER/LEARN] action=move-adopt old=%r new=%r proto_connected=%s age_last_rtt=%s",
                    cur,
                    full_addr,
                    proto_connected,
                    ("n/a" if age_s is None else f"{age_s:.3f}s"),
                )
                self.send_port.set_peer(full_addr)
                if callable(self.on_peer_set):
                    self.on_peer_set(host, port)
            else:
                log.debug(
                    "[PEER/LEARN] action=move-delay old=%r new=%r proto_connected=%s age_last_rtt=%s grace_s=%.3f",
                    cur,
                    full_addr,
                    proto_connected,
                    ("n/a" if age_s is None else f"{age_s:.3f}s"),
                    self._move_grace_ns / 1e9,
                )

    def _parse_and_count(self, data: bytes):
        parsed = self.proto.parse_frame_with_times(data)
        if not parsed:
            self._unidentified_frames += 1
            return None, None, 0, 0
        ptype, payload, tx_ns, echo_ns = parsed
        if ptype == PTYPE_DATA:
            dp = DataPacket.parse_payload(payload, data)
            if dp is None:
                self._unidentified_frames += 1
                return None, None, 0, 0
            return "data", dp, tx_ns, echo_ns
        if ptype == self.proto.PTYPE_CONTROL:
            cp = ControlPacket.parse_payload(payload, data)
            if cp is None:
                self._unidentified_frames += 1
                return None, None, 0, 0
            return "control", cp, tx_ns, echo_ns
        if ptype == self.proto.PTYPE_IDLE:
            return "idle", None, tx_ns, echo_ns
        self._unidentified_frames += 1
        return None, None, 0, 0

    def _emit_control(self, now_t: int, reason: str = "timer_paced"):
        if self.send_port is None:
            return
        ctl = self.session.build_control()
        try:
            self.send_port.sendto(ctl.raw)
        except Exception:
            return
        self._last_control_sent_ns = now_t
        self._last_sent_last_in_order = self.session.last_in_order()
        if self.session.log.isEnabledFor(logging.DEBUG):
            try:
                self.session.log.debug(f"[CTL->] reason={reason} LIO={ctl.last_in_order_rx} HI={ctl.highest_rx} missed={len(ctl.missed)} head={ctl.missed[:12]}")
            except Exception:
                pass



    # ---- control policy (owner: PeerProtocol) ----
    def _evaluate_control_policy_inbound(self, grew_missing: bool):
        now_t = now_ns()
        last_in_order = self.session.last_in_order()
        miss_count = len(self.session.missing)
        if grew_missing:
            self._emit_control(now_t, reason="inbound_grew_missing")
            return
        if miss_count == 0:
            if ring_cmp(last_in_order, self._last_sent_last_in_order) > 0:
                ref = self._last_control_sent_ns or self._established_ns
                interval = int(0.5 * (self.proto.rtt_est_ms / 1000.0) * 1e9)
                elapsed = (now_t - ref) >= interval if ref else True
                if elapsed:
                    self._emit_control(now_t, reason="advanced_in_order")
                return
        if miss_count > 0:
            interval = int(0.5 * (self.proto.rtt_est_ms / 1000.0) * 1e9)
            last = self._last_control_sent_ns
            elapsed = (now_t - last) >= interval if last else True
            if elapsed:
                self._emit_control(now_t, reason="paced_with_missing")
    def _evaluate_control_policy_timer(self):
        now_t = now_ns()
        last_in_order = self.session.last_in_order()
        miss_count = len(self.session.missing)
        if miss_count == 0:
            if ring_cmp(last_in_order, self._last_sent_last_in_order) > 0:
                ref = self._last_control_sent_ns or self._established_ns
                interval = int(0.5 * (self.proto.rtt_est_ms / 1000.0) * 1e9)
                if ref and (now_t - ref) >= interval:
                    self._emit_control(now_t, reason="timer_paced_clear_miss")
                return
        if miss_count > 0:
            interval = int(0.5 * (self.proto.rtt_est_ms / 1000.0) * 1e9)
            last = self._last_control_sent_ns
            elapsed = (now_t - last) >= interval if last else True
            if elapsed:
                self._emit_control(now_t, reason="timer_paced_with_missing")
    # ---- loss mitigation (owner: PeerProtocol) ----
    def _schedule_retrans(self, missed: List[int]) -> None:
        if self.send_port is None or not missed:
            self.session.peer_missed_count = len(missed)
            return
        s = self.session
        s.peer_missed_count = len(missed)
        now = now_ns()
        window = int(s.rtt_est_ms * 1e6 * RETRANS_MULTIPLIER)
        retx_list: List[int] = []
        for cnt in missed:
            if cnt == 0:
                continue
            meta = s.send_meta.get(cnt)
            if not meta:
                raw = s.send_buf.get(cnt)
                if not raw:
                    continue
                last = s.last_retx_ns.get(cnt, 0)
                if last and (now - last) < window:
                    continue
                try:
                    self.send_port.sendto(raw)
                except Exception:
                    continue
                s.last_retx_ns[cnt] = now
                s.last_send_ns = now
                s._bump_attempt(cnt)
                retx_list.append(cnt)
                continue
            last = s.last_retx_ns.get(cnt, 0)
            if last and (now - last) < window:
                continue
            frame_type, off_or_len, chunk = meta
            payload = DataPacket.build_payload(cnt, frame_type, off_or_len, chunk, now)
            frame = self.proto.build_frame(PTYPE_DATA, payload)
            try:
                self.send_port.sendto(frame)
            except Exception:
                continue
            s.send_buf[cnt] = frame
            s.last_retx_ns[cnt] = now
            s.last_send_ns = now
            s._bump_attempt(cnt)
            retx_list.append(cnt)
        if self.session.log.isEnabledFor(logging.DEBUG) and retx_list:
            self.session.log.debug(f"[RTX] due_to_control cnts={sorted(retx_list)[:32]}{'…' if len(retx_list)>32 else ''} window_ms={s.rtt_est_ms*RETRANS_MULTIPLIER:.2f}")
    def _retx_sweep_unconfirmed(self) -> None:
        if self.send_port is None:
            return
        s = self.session
        if not s.send_buf:
            return
        now = now_ns()
        window = int(s.rtt_est_ms * 1e6 * RETRANS_MULTIPLIER)
        retx_list: List[int] = []
        for cnt, raw in list(s.send_buf.items()):
            if cnt == 0:
                continue
            last_retx = s.last_retx_ns.get(cnt, 0)
            first_tx = s.send_txns.get(cnt, 0)
            last_any = max(last_retx, first_tx)
            if window and (now - last_any) < window:
                continue
            meta = s.send_meta.get(cnt)
            if meta is None:
                try:
                    self.send_port.sendto(raw)
                except Exception:
                    continue
                s.last_retx_ns[cnt] = now
                s.last_send_ns = now
                s._bump_attempt(cnt)
                retx_list.append(cnt)
                continue
            frame_type, off_or_len, chunk = meta
            payload = DataPacket.build_payload(cnt, frame_type, off_or_len, chunk, now)
            frame = self.proto.build_frame(PTYPE_DATA, payload)
            try:
                self.send_port.sendto(frame)
            except Exception:
                continue
            s.send_buf[cnt] = frame
            s.last_retx_ns[cnt] = now
            s.last_send_ns = now
            s._bump_attempt(cnt)
            retx_list.append(cnt)
        if self.session.log.isEnabledFor(logging.DEBUG) and retx_list:
            self.session.log.debug(f"[RTX] timeout_sweep cnts={sorted(retx_list)[:32]}{'…' if len(retx_list)>32 else ''} window_ms={s.rtt_est_ms*RETRANS_MULTIPLIER:.2f}")
    # ---- asyncio protocol ----
    def datagram_received(self, data: bytes, addr):
        self.session.log.debug(
            "[PEER/RX/RAW-SOCKET] len=%d from=%r transport_sock=%r transport_peer=%r",
            len(data),
            addr,
            (self.udp_transport.get_extra_info("sockname") if self.udp_transport else None),
            (self.udp_transport.get_extra_info("peername") if self.udp_transport else None),
        )
        # --- NEW: per-datagram RX visibility (DEBUG) ---
        try:
            # Resolve endpoints for logging
            l_sock = self.udp_transport.get_extra_info("sockname") if self.udp_transport else None
            p_sock = self.udp_transport.get_extra_info("peername") if self.udp_transport else None
            src = (addr[0], int(addr[1])) if isinstance(addr, tuple) and len(addr) >= 2 else (
                (p_sock[0], int(p_sock[1])) if isinstance(p_sock, tuple) and len(p_sock) >= 2 else None)
            dst = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None
            self.session.log.debug(f"[PEER/RX] {len(data)}B <- {dst} <- {src} ")
        except Exception as e:
            self.log.debug(f"[PEER/RX] Incoming data logging failed : %r",e)
            pass
        cur_peer_before = None
        try:
            cur_peer_before = self.send_port.peer_addr if self.send_port else None
        except Exception:
            cur_peer_before = None

        self.session.log.debug(
            "[PEER/RX/STATE-BEFORE] from=%r current_peer=%r runtime_attached=%s proto_connected=%s last_rtt_ok_ns=%s",
            addr,
            cur_peer_before,
            self._runtime_attached,
            self.proto.is_connected(),
            getattr(self.proto, "last_rtt_ok_ns", 0),
        )            

        try:
            host, port = str(addr[0]), int(addr[1])            
        except Exception:
            pass

        # (existing code follows)
        if callable(self._on_peer_rx_bytes):
            try:
                self._on_peer_rx_bytes(len(data))
            except Exception:
                pass
        self.notify_send_port_ready()
        self._maybe_learn_peer(addr)

        cur_peer_after = None
        try:
            cur_peer_after = self.send_port.peer_addr if self.send_port else None
        except Exception:
            cur_peer_after = None

        self.session.log.debug(
            "[PEER/RX/STATE-AFTER-LEARN] from=%r current_peer=%r changed=%s",
            addr,
            cur_peer_after,
            (cur_peer_after != cur_peer_before),
        )

        now_t = now_ns()
        kind, pkt, tx_ns, echo_ns = self._parse_and_count(data)
        self.session.log.debug(
            "[PEER/RX/PARSE] from=%r kind=%r tx_ns=%d echo_ns=%d pkt=%s",
            addr,
            kind,
            tx_ns,
            echo_ns,
            type(pkt).__name__ if pkt is not None else None,
        )

        self.proto.on_frame_received(tx_ns, now_t)
        if echo_ns:
            self.session.log.debug(
                "[PEER/RX/RTT-SUCCESS-PATH] from=%r tx_ns=%d echo_ns=%d proto_connected_before=%s",
                addr, tx_ns, echo_ns, self.proto.is_connected()
            )
            prev_sample = getattr(self.session, "rtt_sample_ms", 0.0)
            prev_est = getattr(self.session, "rtt_est_ms", 0.0)
            self.session.log.debug(
                "[PEER/RX/RTT] action=update from=%r echo_ns=%d prev_sample_ms=%.3f prev_est_ms=%.3f",
                addr,
                echo_ns,
                prev_sample,
                prev_est,
            )
            self.session.update_rtt(echo_ns)
            self.session.log.debug(
                "[PEER/RX/RTT] action=updated from=%r sample_ms=%.3f est_ms=%.3f last_rtt_ok_ns=%d",
                addr,
                getattr(self.session, "rtt_sample_ms", 0.0),
                getattr(self.session, "rtt_est_ms", 0.0),
                getattr(self.session, "last_rtt_ok_ns", 0),
            )
            if self._established_ns == 0:
                self._established_ns = now_ns()
            if callable(self._on_rtt_success):
                try:
                    self._on_rtt_success(echo_ns)
                except Exception:
                    pass
        else:
            self.session.log.debug(
                "[PEER/RX/RTT] action=skip from=%r reason=echo_ns_zero kind=%r",
                addr,
                kind,
            )
        if kind == "idle":
            #  Reflect only initial idle probes (echo==0)
            if echo_ns == 0:
                try:
                    # reflect WITHOUT initial flag => echo gets filled
                    frame = self.proto.build_frame(self.proto.PTYPE_IDLE, b"", initial=False)
                    self.session.log.debug(
                        "[PEER/TX/FRAME] reason=idle-reflect to=%r ptype=%s tx_ns=%d echo_ns=%d current_peer=%r frame_len=%d",
                        (self.send_port.peer_addr if self.send_port else None),
                        self.proto.PTYPE_IDLE,
                        getattr(self.proto, "last_send_ns", 0),
                        getattr(self.proto, "_last_rx_tx_ns", 0),
                        (self.send_port.peer_addr if self.send_port else None),
                        len(frame),
                    )
                    self.send_port.sendto(frame)
                except Exception:
                    pass
            self.session.log.debug(
                "[IDLE/DECISION] from=%r echo_ns=%d will_reflect=%s",
                addr, echo_ns, echo_ns == 0
            )                    
            return
        if kind == "data" and pkt:
            prev_missing = set(self.session.missing)
            _, completed = self.session.process_data(pkt)
            if (pkt.pkt_counter in prev_missing) and (pkt.pkt_counter not in self.session.missing):
                self._emit_control(now_ns(), reason="gap_filled_ack")
            grew_missing = len(self.session.missing - prev_missing) > 0
            self._evaluate_control_policy_inbound(grew_missing)
            for c in completed:
                self.session.log.debug(f"[PeerProtocol] On Complete  on session id=%x", id(self))
                self.on_complete(c)
            return
        if kind == "control" and pkt:
            cp: ControlPacket = pkt
            self.session.confirm_with_feedback(cp.last_in_order_rx, cp.highest_rx, cp.missed)
            self._schedule_retrans(cp.missed)
            if self.send_port:
                self.session.try_flush_send_queue(self.send_port)
            self._evaluate_control_policy_inbound(False)

    # ---- timers (PeerProtocol ownership) ----
    def controltimerstart(self):
        self._ctl_task = None
        try:
            loop = asyncio.get_running_loop()
            self._ctl_task = loop.create_task(self._control_tick())
        except RuntimeError:
            self._ctl_task = None

    def controltimerstop(self):
        if self._ctl_task:
            self._ctl_task.cancel()
            self._ctl_task = None

    async def _control_tick(self):
        try:
            while True:
                await asyncio.sleep(0.025)
                self._evaluate_control_policy_timer()
        except asyncio.CancelledError:
            return

    def retxtimerstart(self):
        self._retx_task = None
        try:
            loop = asyncio.get_running_loop()
            self._retx_task = loop.create_task(self._retx_tick())
        except RuntimeError:
            self._retx_task = None

    def retxtimerstop(self):
        if self._retx_task:
            self._retx_task.cancel()
            self._retx_task = None
    async def _retx_tick(self):
        try:
            while True:
                await asyncio.sleep(RETRANSMIT_UNCONFIRMED_MS / 1000.0)
                self._retx_sweep_unconfirmed()
        except asyncio.CancelledError:
            return

    # Convenience pass-through for tests
    def send_idle_ping(self, initial=False) -> None:
        self._proto_rt._send_idle_probe(initial)

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        return await self._proto_rt.wait_connected(timeout)

# -----------------------------------------------------------------------------

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

class UdpSession(ISession):
    """
    Adapter that owns the existing UDP overlay:
      - creates asyncio UDP endpoint and PeerProtocol internally,
      - exposes ISession methods to the rest of the app (Mux/Runner).
    No behavior changes vs. old Runner wiring.  
    """
    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._log = logging.getLogger("udp_session")
        DebugLoggingConfigurator.debug_logger_status(self._log)

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._proto_state = PROTO.__class__(BaseFrameV2)
        self._proto: Optional[PeerProtocol] = None
        self.peer_proto: Optional[PeerProtocol] = None
        self._peer_host: str = ""
        self._peer_port: int = 0
        self._listener_mode: bool = False
        self._listener_connected: bool = False
        self._server_connected_evt: asyncio.Event = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_peer_by_addr: Dict[Tuple[str, int], int] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1

        # Inner reliability/session engine remains the same one from base module.
        self.inner_session = Session(max_in_flight=args.max_inflight, proto=self._proto_state)

        # Callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # Optional peer-frame mirror (debug) — installed by Runner when flags are set
        self._peer_mirror_out: Optional[Callable[[bytes], None]] = None
        self._peer_mirror_in: Optional[Callable[[bytes], None]] = None
        self._peer_mirror_installed: bool = False

    # ---------- CLI integration ----------
    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        """
        Overlay/Session-level flags. Defaults = current behavior.
        """
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False

        # Overlay (peer) side
        if not _has('--udp-bind'):
            p.add_argument('--udp-bind', dest='udp_bind', default='::',
                           help="overlay bind address (IPv4 '0.0.0.0' or IPv6 '::')")
        if not _has('--udp-own-port'):
            p.add_argument('--udp-own-port', dest='udp_own_port', type=int, default=4433, help='overlay own port')
        if not _has('--udp-peer'):
            p.add_argument('--udp-peer', '--peer', dest='udp_peer', default=None,
                           help="peer IP/FQDN (IPv4 or IPv6 literal; IPv6 may be in [brackets])")
        if not _has('--udp-peer-port'):
            p.add_argument('--udp-peer-port', '--peer-port', dest='udp_peer_port', type=int, default=4433, help='peer overlay port')
        if not _has('--peer-resolve-family'):
            p.add_argument(
                '--peer-resolve-family',
                choices=['prefer-ipv6', 'ipv4', 'ipv6'],
                default='prefer-ipv6',
                help='Peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.'
            )

        # Session window
        if not _has('--max-inflight'):
            p.add_argument('--max-inflight', type=int, default=32767,
                           help='max DATA frames allowed in flight (1..32767). Excess frames are queued.')

    @staticmethod
    def from_args(args: argparse.Namespace) -> "UdpSession":
        """
        Build a UdpSession from parsed CLI args (no behavior change).
        """
        return UdpSession(args)


    # ---- ISession: callback wiring ----
    def set_on_app_payload(self, cb: Callable[[bytes], None]) -> None:
        self._log.info("[UDP/SESSION] set_on_app_payload wired: cb=%r on session id=%x", cb, id(self))
        self._on_app = cb

    def set_on_state_change(self, cb: Callable[[bool], None]) -> None:
        self._log.debug("[UDP/SESSION] set_on_state_change wired: cb=%r on session id=%x", cb, id(self))
        self._on_state = cb

    def set_on_peer_rx(self, cb: Callable[[int], None]) -> None:
        self._log.debug("[UDP/SESSION] set_on_peer_rx wired: cb=%r on session id=%x", cb, id(self))
        self._on_peer_rx = cb

    def set_on_peer_tx(self, cb: Callable[[int], None]) -> None:
        self._log.debug("[UDP/SESSION] set_on_peer_tx wired: cb=%r on session id=%x", cb, id(self))
        self._on_peer_tx = cb

    def set_on_peer_set(self, cb: Callable[[str, int], None]) -> None:
        self._log.debug("[UDP/SESSION] set_on_peer_set wired: cb=%r on session id=%x", cb, id(self))
        self._on_peer_set_cb = cb

    def set_on_peer_disconnect(self, cb: Callable[[int], None]) -> None:
        self._on_peer_disconnect_cb = cb

    def set_on_app_from_peer_bytes(self, cb: Callable[[int], None]) -> None:
        self._log.debug("[UDP/SESSION] set_on_app_from_peer_bytes wired: cb=%r on session id=%x", cb, id(self))
        self._on_app_from_peer_bytes = cb

    def set_on_transport_epoch_change(self, cb: Callable[[int], None]) -> None:
        self._on_transport_epoch_change = cb


    def get_metrics(self) -> SessionMetrics:
        if self._listener_mode and self._server_peers:
            try:
                sessions = [ctx["session"] for ctx in self._server_peers.values() if isinstance(ctx, dict) and ctx.get("session") is not None]
                rtt_candidates = [float(getattr(s, "rtt_est_ms", 0.0) or 0.0) for s in sessions if getattr(s, "last_rtt_ok_ns", 0)]
                last_rtt_ok = max((int(getattr(s, "last_rtt_ok_ns", 0) or 0) for s in sessions), default=0)
                return SessionMetrics(
                    rtt_est_ms=max(rtt_candidates) if rtt_candidates else None,
                    last_rtt_ok_ns=last_rtt_ok or None,
                    inflight=sum(int(s.in_flight()) for s in sessions if hasattr(s, "in_flight")),
                    max_inflight=sum(int(getattr(s, "max_in_flight", 0) or 0) for s in sessions),
                    waiting_count=sum(int(s.waiting_count()) for s in sessions if hasattr(s, "waiting_count")),
                    peer_missed_count=sum(int(getattr(s, "peer_missed_count", 0) or 0) for s in sessions),
                    our_missed_count=sum(len(getattr(s, "missing", [])) for s in sessions if hasattr(s, "missing")),
                )
            except Exception as e:
                self._log.debug("[UdpSession] aggregated get_metrics failed %r", e)
        s = self.inner_session
        try:
            return SessionMetrics(
                rtt_sample_ms     = getattr(s, "rtt_sample_ms", None),
                rtt_est_ms        = getattr(s, "rtt_est_ms", None),
                last_rtt_ok_ns    = getattr(s, "last_rtt_ok_ns", None),
                inflight          = int(s.in_flight()) if hasattr(s, "in_flight") else None,
                max_inflight      = getattr(s, "max_in_flight", None),
                waiting_count     = int(s.waiting_count()) if hasattr(s, "waiting_count") else None,
                last_ack_peer     = getattr(s, "last_ack_peer", None),
                last_sent_ctr     = getattr(s, "last_sent_ctr", None),
                expected          = getattr(s, "expected", None),
                peer_missed_count = getattr(s, "peer_missed_count", None),
                our_missed_count  = len(getattr(s, "missing", [])) if hasattr(s, "missing") else None,
            )
        except Exception as e:
            self._log.debug(f"[UdpSession] get_metrics failed on SessionMetrics(..) %r", e)
            return SessionMetrics()

    @staticmethod
    def _format_peer_label(host: Optional[object], port: Optional[object]) -> Optional[str]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return f"[{host_s}]:{port_i}" if ":" in host_s and not host_s.startswith("[") else f"{host_s}:{port_i}"
        except Exception:
            return None

    @staticmethod
    def _extract_quic_peer_addr(proto: Any) -> Tuple[Optional[str], Optional[int]]:
        try:
            quic = getattr(proto, "_quic", None)
            paths = getattr(quic, "_network_paths", None) if quic is not None else None
            if paths:
                addr = getattr(paths[0], "addr", None)
                if isinstance(addr, tuple) and len(addr) >= 2:
                    return str(addr[0]), int(addr[1])
        except Exception:
            pass
        try:
            transport = getattr(proto, "_transport", None)
            peer = transport.get_extra_info("peername") if transport is not None else None
            if isinstance(peer, tuple) and len(peer) >= 2:
                return str(peer[0]), int(peer[1])
        except Exception:
            pass
        return None, None

    def get_overlay_peers_snapshot(self) -> list[dict]:
        if self._listener_mode:
            rows: list[dict] = []
            mux_by_peer: Dict[int, list[int]] = {}
            for mux_chan, mapped in self._server_chan_to_peer.items():
                try:
                    peer_id, _peer_chan = mapped
                    mux_by_peer.setdefault(int(peer_id), []).append(int(mux_chan))
                except Exception:
                    continue
            rows.append({
                "peer_id": -1,
                "connected": False,
                "peer": None,
                "mux_chans": [],
                "rtt_est_ms": None,
                "listening": True,
            })
            for peer_id in sorted(self._server_peers.keys()):
                ctx = self._server_peers.get(peer_id, {})
                addr = ctx.get("addr") if isinstance(ctx, dict) else None
                host = addr[0] if isinstance(addr, tuple) and len(addr) >= 2 else None
                port = addr[1] if isinstance(addr, tuple) and len(addr) >= 2 else None
                session = ctx.get("session") if isinstance(ctx, dict) else None
                rows.append({
                    "peer_id": peer_id,
                    "connected": bool(ctx.get("connected")) if isinstance(ctx, dict) else False,
                    "peer": self._format_peer_label(host, port),
                    "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                    "rtt_est_ms": getattr(session, "rtt_est_ms", None),
                })
            return rows
        peer_label = None
        with contextlib.suppress(Exception):
            if self._proto is not None and self._proto.send_port is not None:
                peer = getattr(self._proto.send_port, "peer_addr", None)
                if isinstance(peer, tuple) and len(peer) >= 2:
                    peer_label = self._format_peer_label(peer[0], peer[1])
        if not peer_label:
            peer_label = self._format_peer_label(self._peer_host, self._peer_port)
        return [{
            "peer_id": 0,
            "connected": bool(self.is_connected()),
            "peer": peer_label,
            "mux_chans": [],
            "rtt_est_ms": getattr(self.inner_session, "rtt_est_ms", None),
        }]


    # ---- ISession: lifecycle ----
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        listen_host = _strip_brackets(getattr(self._args, "udp_bind", "::"))
        listen_port = int(getattr(self._args, "udp_own_port", 4433))
        peer_info = _resolve_cli_peer(
            self._args,
            peer_attr="udp_peer",
            peer_port_attr="udp_peer_port",
            bind_host=listen_host,
            socktype=socket.SOCK_DGRAM,
        )
        peer = None
        peer_family = socket.AF_UNSPEC
        if peer_info is not None:
            peer_host, peer_port, peer_family = peer_info
            peer = (peer_host, peer_port)
        self._listener_mode = peer is None

        if (
            not _prefer_unspec_listener_family()
            and listen_host in ('::', '0.0.0.0')
            and peer_family in (socket.AF_INET, socket.AF_INET6)
        ):
            family = peer_family
            listen_host = _wildcard_host_for_family(peer_family)
        else:
            family = _listener_family_for_host(listen_host)
        listen = (listen_host, listen_port)

        def _factory():
            if self._listener_mode:
                return self._ListenerDatagramProtocol(self)
            self._log.debug(f"[UDP/SESSION] Initiate Peerprotocol with peer {peer}")
            return PeerProtocol(
                self.inner_session,
                self._on_control_needed,
                self._on_complete,
                peer=peer,
                proto=self._proto_state,
                on_peer_set=self._on_peer_set,
                on_peer_rx_bytes=self._on_peer_rx_bytes,
                on_peer_tx_bytes=self._on_peer_tx_bytes,
                on_rtt_success=self._on_rtt_success,
                on_state_change=self._on_state_change,
            )

        sock = None

        try:
            # Model B:
            # Always use an unconnected UDP socket.
            # On Windows, prepare the socket manually so we can disable
            # UDP connreset / ICMP port unreachable poisoning.
            if os.name == "nt":
                win_family = family if family != socket.AF_UNSPEC else (
                    socket.AF_INET6 if ":" in listen_host else socket.AF_INET
                )
                sock = socket.socket(win_family, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.bind(listen)
                try:
                    sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except Exception as e:
                    self._log.warning("Could not disable SIO_UDP_CONNRESET: %r", e)

                self._log.debug(
                    "[UDP/SESSION] Initiate unconnected Data Endpoint via prebuilt socket local=%r initial_peer=%r",
                    listen,
                    peer,
                )
                transport, protocol = await self._loop.create_datagram_endpoint(
                    _factory,
                    sock=sock,
                )
            else:
                self._log.debug(
                    "[UDP/SESSION] Initiate unconnected Data Endpoint local=%r initial_peer=%r",
                    listen,
                    peer,
                )
                transport, protocol = await self._loop.create_datagram_endpoint(
                    _factory,
                    local_addr=listen,
                    family=family,
                )
        except Exception as e:
            self._log.error(
                "[UdpSession] Create Data Endpoint %r family=%r failed: %r",
                listen,
                family,
                e,
            )
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
            return

        self._transport = transport
        if self._listener_mode:
            self._proto = None
        else:
            self._proto = protocol
            self.peer_proto = protocol

        # Model B:
        # Seed only the protocol-layer peer. The UDP socket itself stays unconnected.
        if (not self._listener_mode) and peer is not None:
            try:
                host, port = peer
                self._on_peer_set(host, port)
                sp = getattr(self._proto, "send_port", None)
                if sp:
                    sp.set_peer((host, port))
            except Exception as e:
                self._log.debug("[UdpSession] start failed on set_peer %r", e)

    async def stop(self) -> None:
        try:
            for peer_id in list(self._server_peers.keys()):
                await self._close_server_peer(peer_id)
            if self._transport:
                self._transport.close()
        finally:
            self._transport = None
            self._proto = None
            self.peer_proto = None
            self._server_connected_evt.clear()
            self._listener_connected = False
        
    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if self._listener_mode:
            if self.is_connected():
                return True
            try:
                await asyncio.wait_for(self._server_connected_evt.wait(), timeout)
                return True
            except asyncio.TimeoutError:
                return False
        return await (self._proto.wait_connected(timeout) if self._proto else asyncio.sleep(timeout or 0, result=False))

    def is_connected(self) -> bool:
        if self._listener_mode:
            return any(bool(ctx.get("connected")) for ctx in self._server_peers.values())
        return self._proto_state.is_connected()

    # ---- ISession: data path ----
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        self._log.debug(f"[UdpSession] send_app len {len(payload)}  on session id=%x", id(self))
        if not payload:
            return 0
        if self._listener_mode:
            target = self._resolve_server_send_target(payload, peer_id=peer_id)
            if target is None:
                return 0
            target_peer_id, routed_payload = target
            ctx = self._server_peers.get(target_peer_id)
            if not ctx:
                return 0
            proto = ctx.get("peer_proto")
            session = ctx.get("session")
            if proto is None or session is None or getattr(proto, "send_port", None) is None:
                return 0
            return session.send_application_payload(routed_payload, proto.send_port)
        if not self._proto or not self._proto.send_port:
            return 0
        return self.inner_session.send_application_payload(payload, self._proto.send_port)

    # ---- Internals (callbacks given to PeerProtocol) ----
    def _on_control_needed(self) -> None:
        self._log.debug(f"[UdpSession] on_control_needed  on session id=%x", id(self))
        if not self._proto or not self._proto.send_port:
            return
        ctl = self.inner_session.build_control()  
        try:
            self._proto.send_port.sendto(ctl.raw)
        except Exception as e:
            self._log.debug(f"[UdpSession] _on_control_needed failed on _proto.send_port.sendto %r", e)
            pass

    def _on_complete(self, datagram: bytes) -> None:
        self._log.debug(f"[UdpSession] On Complete Datagram len {len(datagram)} on session id=%x", id(self))
        try:
            if datagram and self._on_app_from_peer_bytes:
                self._on_app_from_peer_bytes(len(datagram))
        except Exception as e:
            self._log.debug(f"[UdpSession] _on_complete failed on _on_app_from_peer_bytes %r", e)
            pass
        if callable(self._on_app):
            try:
                self._on_app(datagram)
            except Exception as e:
                self._log.debug(f"[UdpSession] _on_complete failed on _on_app %r", e)

    def _on_complete_for_peer(self, peer_id: int, datagram: bytes) -> None:
        self._log.debug("[UdpSession] On Complete Datagram len %d peer_id=%s on session id=%x", len(datagram), peer_id, id(self))
        try:
            if datagram and self._on_app_from_peer_bytes:
                self._on_app_from_peer_bytes(len(datagram))
        except Exception as e:
            self._log.debug("[UdpSession] _on_complete_for_peer failed on _on_app_from_peer_bytes %r", e)
        if callable(self._on_app):
            try:
                rewritten = self._server_rewrite_inbound_app(peer_id, datagram)
                try:
                    self._on_app(rewritten, peer_id=peer_id)
                except TypeError:
                    self._on_app(rewritten)
            except Exception as e:
                self._log.debug("[UdpSession] _on_complete_for_peer failed on _on_app %r", e)

    def _on_peer_set(self, host: str, port: int) -> None:
        self._log.debug(f"[UdpSession] On Peer Set {host}:{port} on session id=%x", id(self))
        with contextlib.suppress(Exception):
            self._peer_host = str(host or "")
            self._peer_port = int(port or 0)
        # Inform external callback first
        if callable(self._on_peer_set_cb):
            try:
                self._on_peer_set_cb(host, port)
            except Exception as e:
                self._log.debug(f"[UdpSession] _on_peer_set failed on _on_peer_set_cb %r", e)

    def _on_peer_set_for_peer(self, peer_id: int, host: str, port: int) -> None:
        self._log.debug("[UdpSession] On Peer Set %s:%s peer_id=%s on session id=%x", host, port, peer_id, id(self))
        ctx = self._server_peers.get(peer_id)
        if ctx is not None:
            old_addr = ctx.get("addr")
            new_addr = (str(host or ""), int(port or 0))
            if isinstance(old_addr, tuple) and self._server_peer_by_addr.get(old_addr) == peer_id and old_addr != new_addr:
                self._server_peer_by_addr.pop(old_addr, None)
            ctx["addr"] = new_addr
            self._server_peer_by_addr[new_addr] = peer_id
        self._on_peer_set(host, port)

    def _on_peer_rx_bytes(self, n: int) -> None:
        self._log.debug(f"[UdpSession] On Peer Rx bytes {n} on session id=%x", id(self))
        if callable(self._on_peer_rx):
            try:
                self._on_peer_rx(n)
            except Exception as e:
                self._log.debug(f"[UdpSession] _on_peer_rx_bytes failed on _on_peer_rx %r", e)

    def _on_peer_tx_bytes(self, n: int) -> None:
        self._log.debug(f"[UdpSession] On Peer Tx bytes {n} on session id=%x", id(self))
        if callable(self._on_peer_tx):
            try:
                self._on_peer_tx(n)
            except Exception as e:
                self._log.debug(f"[UdpSession] _on_peer_tx_bytes failed on _on_peer_tx %r", e)

    def _on_rtt_success(self, echo_tx_ns: int) -> None:
        # Runner dashboard already reads RTT via PROTO mirrored stats; nothing needed here.  
        self._log.debug(f"[UdpSession] On RTT success {echo_tx_ns} on session id=%x", id(self))
        return

    def _on_rtt_success_for_peer(self, peer_id: int, echo_tx_ns: int) -> None:
        self.peer_proto = self._server_peers.get(peer_id, {}).get("peer_proto") or self.peer_proto
        self._on_rtt_success(echo_tx_ns)

    def _on_state_change(self, connected: bool):
        try:
            peer = None
            if self._proto is not None and self._proto.send_port is not None:
                peer = self.peer_proto.send_port.peer_addr
        except Exception:
            peer = None

        s = self.inner_session

        self._log.info(
            "[UDP/SESSION/STATE] %s peer=%r rtt_sample_ms=%.3f rtt_est_ms=%.3f last_rtt_ok_ns=%d",
            ("CONNECTED" if connected else "DISCONNECTED"),
            peer,
            getattr(s, "rtt_sample_ms", 0.0),
            getattr(s, "rtt_est_ms", 0.0),
            getattr(s, "last_rtt_ok_ns", 0),
        )

        if callable(self._on_state):
            try:
                self._on_state(connected)
            except Exception as e:
                self._log.debug("[UDP/SESSION/STATE] _on_state_change failed on _on_state %r", e)

    def _on_state_change_for_peer(self, peer_id: int, connected: bool) -> None:
        ctx = self._server_peers.get(peer_id)
        if ctx is not None:
            ctx["connected"] = bool(connected)
            self.peer_proto = ctx.get("peer_proto") or self.peer_proto
        self._update_server_connected_state()
        if not connected:
            try:
                self._loop.create_task(self._close_server_peer(peer_id))  # type: ignore[union-attr]
            except Exception as e:
                self._log.debug("[UDP/SESSION/STATE] failed scheduling close for peer_id=%s: %r", peer_id, e)

    class _ListenerDatagramProtocol(asyncio.DatagramProtocol):
        def __init__(self, owner: "UdpSession"):
            self.owner = owner

        def connection_made(self, transport: asyncio.BaseTransport):
            self.owner._transport = transport  # type: ignore[assignment]

        def datagram_received(self, data: bytes, addr):
            self.owner._dispatch_listener_datagram(data, addr)

        def error_received(self, exc):
            self.owner._log.debug("[UDP/LISTENER] error_received exc=%r", exc)

        def connection_lost(self, exc: Optional[Exception]) -> None:
            self.owner._log.debug("[UDP/LISTENER] connection_lost exc=%r", exc)
            for peer_id in list(self.owner._server_peers.keys()):
                ctx = self.owner._server_peers.get(peer_id)
                pp = ctx.get("peer_proto") if isinstance(ctx, dict) else None
                if pp is not None:
                    with contextlib.suppress(Exception):
                        pp.connection_lost(exc)

    def _dispatch_listener_datagram(self, data: bytes, addr) -> None:
        try:
            host, port = str(addr[0]), int(addr[1])
        except Exception:
            return
        key = (host, port)
        peer_id = self._server_peer_by_addr.get(key)
        if peer_id is None:
            peer_id = self._alloc_server_peer_id()
            proto_state = PROTO.__class__(BaseFrameV2)
            session = Session(max_in_flight=self._args.max_inflight, proto=proto_state)
            peer_proto = PeerProtocol(
                session,
                lambda _peer_id=peer_id: self._on_control_needed_for_peer(_peer_id),
                lambda datagram, _peer_id=peer_id: self._on_complete_for_peer(_peer_id, datagram),
                peer=key,
                proto=proto_state,
                on_peer_set=lambda h, p, _peer_id=peer_id: self._on_peer_set_for_peer(_peer_id, h, p),
                on_peer_rx_bytes=self._on_peer_rx_bytes,
                on_peer_tx_bytes=self._on_peer_tx_bytes,
                on_rtt_success=lambda echo_tx_ns, _peer_id=peer_id: self._on_rtt_success_for_peer(_peer_id, echo_tx_ns),
                on_state_change=lambda connected, _peer_id=peer_id: self._on_state_change_for_peer(_peer_id, connected),
            )
            self._server_peers[peer_id] = {
                "peer_id": peer_id,
                "addr": key,
                "session": session,
                "peer_proto": peer_proto,
                "connected": False,
            }
            self._server_peer_by_addr[key] = peer_id
            self.peer_proto = peer_proto
            if self._transport is not None:
                peer_proto.connection_made(self._transport)
            self._log.info("[UDP/SESSION] listener accepted peer_id=%s peer=%s", peer_id, key)
            self._on_peer_set_for_peer(peer_id, host, port)
        ctx = self._server_peers.get(peer_id)
        peer_proto = ctx.get("peer_proto") if isinstance(ctx, dict) else None
        if peer_proto is not None:
            peer_proto.datagram_received(data, key)

    def _alloc_server_peer_id(self) -> int:
        peer_id = self._server_next_peer_id
        while peer_id in self._server_peers:
            peer_id += 1
            if peer_id > 0xFFFF:
                peer_id = 1
        self._server_next_peer_id = 1 if peer_id >= 0xFFFF else (peer_id + 1)
        return peer_id

    def _alloc_server_mux_chan(self) -> int:
        chan = self._server_next_mux_chan
        while chan in self._server_chan_to_peer:
            chan += 2
            if chan > 0xFFFF:
                chan = 1
        self._server_next_mux_chan = 1 if chan >= 0xFFFF else (chan + 2)
        return chan

    def _rewrite_mux_chan_id(self, payload: bytes, new_chan: int) -> bytes:
        hdr = ChannelMux.MUX_HDR
        if len(payload) < hdr.size:
            return payload
        try:
            _old_chan, proto, counter, mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        return hdr.pack(new_chan, proto, counter, mtype, dlen) + payload[hdr.size:hdr.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        hdr = ChannelMux.MUX_HDR
        if len(payload) < hdr.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        key = (int(peer_id), int(peer_chan))
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = int(peer_chan)
            mapped = self._server_chan_to_peer.get(mux_chan)
            if mapped is not None and mapped != key:
                mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if int(key[0]) != int(peer_id):
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _resolve_server_send_target(self, payload: bytes, peer_id: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        hdr = ChannelMux.MUX_HDR
        if len(payload) < hdr.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return None
        if len(payload) < hdr.size + dlen:
            return None
        target_peer_id = int(peer_id) if peer_id is not None else None
        mapped = self._server_chan_to_peer.get(int(mux_chan))
        if target_peer_id is None and mapped is not None:
            target_peer_id = int(mapped[0])
        if target_peer_id is None:
            if len(self._server_peers) == 1:
                target_peer_id = next(iter(self._server_peers.keys()))
            else:
                return None
        target_ctx = self._server_peers.get(target_peer_id)
        if not target_ctx:
            return None
        peer_chan = int(mux_chan)
        if mapped is not None:
            if int(mapped[0]) != target_peer_id:
                return None
            peer_chan = int(mapped[1])
        else:
            key = (target_peer_id, int(mux_chan))
            self._server_peer_chan_to_mux[key] = int(mux_chan)
            self._server_chan_to_peer[int(mux_chan)] = key
        return target_peer_id, self._rewrite_mux_chan_id(payload, peer_chan) if peer_chan != int(mux_chan) else payload

    def _update_server_connected_state(self) -> None:
        connected = any(bool(ctx.get("connected")) for ctx in self._server_peers.values())
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        if connected == self._listener_connected:
            return
        self._listener_connected = connected
        if callable(self._on_state):
            try:
                self._on_state(connected)
            except Exception as e:
                self._log.debug("[UDP/SESSION/STATE] _update_server_connected_state failed on _on_state %r", e)

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        addr = ctx.get("addr")
        if isinstance(addr, tuple) and self._server_peer_by_addr.get(addr) == peer_id:
            self._server_peer_by_addr.pop(addr, None)
        self._server_unregister_peer_channels(peer_id)
        pp = ctx.get("peer_proto")
        if pp is not None:
            with contextlib.suppress(Exception):
                pp.connection_lost(None)
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception as e:
                self._log.debug("[UDP/SESSION] peer_disconnect callback err: %r", e)
        self._update_server_connected_state()

    def _on_control_needed_for_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.get(peer_id)
        if not ctx:
            return
        session = ctx.get("session")
        pp = ctx.get("peer_proto")
        if session is None or pp is None or getattr(pp, "send_port", None) is None:
            return
        ctl = session.build_control()
        try:
            pp.send_port.sendto(ctl.raw)
        except Exception as e:
            self._log.debug("[UdpSession] _on_control_needed_for_peer failed peer_id=%s err=%r", peer_id, e)

# -----------------------------------------------------------------------------

# ======== Common RTT over stream transports (TCP / WebSocket / QUIC) ========
import struct
import time
import asyncio
from typing import Optional, Callable

def _now_ns() -> int:
    return time.monotonic_ns()

# ======== Common RTT over stream transports (TCP / WebSocket / QUIC) ========
import struct
import time
import asyncio
import logging
from typing import Optional, Callable

def _now_ns() -> int:
    return time.monotonic_ns()

class StreamRTT:
    """
    Transport-agnostic RTT estimator & 'connectedness' window.

    PING : [tx_ns:Q][echo_ns:Q]  (echo_ns may be 0 if unknown)
    PONG : [echo_tx_ns:Q]
    """
    def __init__(self, alpha: float = 0.125, connected_loss_s: float = 20.0,
                 log: Optional[logging.Logger] = None):
        self.rtt_est_ms: float = 0.0
        self.rtt_sample_ms: float = 0.0
        self.last_rtt_ok_ns: int = 0
        self._alpha = float(alpha)
        self._loss_window_ns = int(connected_loss_s * 1e9)
        # For echo computation on our next PING
        self._last_rx_tx_ns: int = 0
        self._last_rx_wall_ns: int = 0
        self._log = log

    def is_connected(self, now_ns_val: Optional[int] = None) -> bool:
        if self.last_rtt_ok_ns == 0:
            return False
        now_v = now_ns_val or _now_ns()
        return (now_v - self.last_rtt_ok_ns) <= self._loss_window_ns

    # --- echo helpers ---
    def on_ping_received(self, tx_ns: int) -> None:
        self._last_rx_tx_ns = int(tx_ns)
        self._last_rx_wall_ns = _now_ns()
        if self._log and self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(f"[RTT] PING rx: tx_ns={tx_ns} wall_ns={self.last_rtt_ok_ns}")

    def build_ping_bytes(self) -> bytes:
        tx_ns = _now_ns()
        echo_ns = 0
        if self._last_rx_tx_ns and self._last_rx_wall_ns:
            echo_ns = self._last_rx_tx_ns + (tx_ns - self._last_rx_wall_ns)
        if self._log and self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(f"[RTT] PING tx: tx_ns={tx_ns} echo_ns={echo_ns}")
        return struct.pack(">QQ", tx_ns, echo_ns)

    def build_pong_bytes(self, echo_tx_ns: int) -> bytes:
        return struct.pack(">Q", int(echo_tx_ns))

    def on_pong_received(self, echo_tx_ns: int) -> None:
        if not echo_tx_ns:
            return
        sample_ms = (_now_ns() - int(echo_tx_ns)) / 1e6
        self.rtt_sample_ms = sample_ms
        self.last_rtt_ok_ns = _now_ns()
        if self.rtt_est_ms < sample_ms:
            self.rtt_est_ms = sample_ms
        else:
            self.rtt_est_ms = (1.0 - self._alpha) * self.rtt_est_ms + self._alpha * sample_ms
        if self._log and self._log.isEnabledFor(logging.DEBUG):
            self._log.debug(
                f"[RTT] PONG rx: echo_tx_ns={echo_tx_ns} "
                f"sample_ms={sample_ms:.3f} est_ms={self.rtt_est_ms:.3f} last_ok={self.last_rtt_ok_ns}"
            )

class StreamRTTRuntime:
    """
    Timer that drives initial and periodic pings and exposes connection events
    based on StreamRTT.is_connected(). Behavior mirrors ProtocolRuntime.
    """
    def __init__(self, rtt: StreamRTT):
        self.rtt = rtt
        self._send_ping_fn: Optional[Callable[[bytes], None]] = None
        self._on_state_change: Optional[Callable[[bool], None]] = None
        self._task: Optional[asyncio.Task] = None
        self._conn_evt = asyncio.Event()
        self._conn_state = False
        self._probe_interval_s = 1.0
        self._idle_check_s = 0.2
        self._rtt_timeout_ns = int(2.0 * 1e9)
        self._next_probe_due_ns = 0

    def attach(self, send_ping_fn: Optional[Callable[[bytes], None]], on_state_change=None):
        self._send_ping_fn = send_ping_fn
        self._on_state_change = on_state_change
        if self._task is None:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._tick())

    def detach(self):
        if self._task:
            self._task.cancel()
            self._task = None
        self._send_ping_fn = None
        self._on_state_change = None
        self._conn_evt.clear()
        self._conn_state = False
        self._next_probe_due_ns = 0

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if self.rtt.is_connected():
            return True
        try:
            await asyncio.wait_for(self._conn_evt.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _send_ping(self) -> None:
        if not self._send_ping_fn:
            return
        try:
            payload = self.rtt.build_ping_bytes()
            self._send_ping_fn(payload)  # Session will wrap as PING frame
        except Exception:
            pass

    async def _tick(self):
        try:
            while True:
                connected_now = self.rtt.is_connected()
                if connected_now != self._conn_state:
                    self._conn_state = connected_now
                    if connected_now:
                        last_ok = self.rtt.last_rtt_ok_ns or _now_ns()
                        self._next_probe_due_ns = last_ok + self._rtt_timeout_ns
                        self._conn_evt.set()
                    else:
                        self._conn_evt.clear()
                        self._next_probe_due_ns = 0
                    if callable(self._on_state_change):
                        try: self._on_state_change(connected_now)
                        except Exception: pass

                if not connected_now:
                    self._send_ping()
                    await asyncio.sleep(self._probe_interval_s)
                    continue

                now = _now_ns()
                last_ok = self.rtt.last_rtt_ok_ns
                if last_ok:
                    self._next_probe_due_ns = max(
                        self._next_probe_due_ns, last_ok + self._rtt_timeout_ns
                    )
                if self._next_probe_due_ns and now >= self._next_probe_due_ns:
                    self._send_ping()
                    self._next_probe_due_ns = now + self._rtt_timeout_ns
                await asyncio.sleep(self._idle_check_s)
        except asyncio.CancelledError:
            return

# -----------------------------------------------------------------------------

class TcpStreamSession(ISession):
    """
    Overlay Session over one TCP stream with an internal control sub-framing:

      frame := LEN(4) + KIND(1) + BYTES...
        KIND=0x00 -> APP (forward to upper layer)
        KIND=0x01 -> PING (payload: Q tx_ns, Q echo_ns)  -- internal
        KIND=0x02 -> PONG (payload: Q echo_tx_ns)        -- internal

    Features:
      - OS-level TCP keepalive on accept/connect
      - Proactive connect on start() in client mode + auto-reconnect with backoff
      - RTT runtime (StreamRTTRuntime) -> drives overlay "connected" state
      - Backpressure + early buffering (APP frames)
      - Per-connection counters + running CRC32 over wire bytes (LEN+KIND+payload)
    """
    # stream kinds
    _K_APP  = 0x00
    _K_PING = 0x01
    _K_PONG = 0x02

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        """
        TCP overlay backpressure knobs (disabled-by-default time-based).
        - --tcp-bp-wbuf-threshold: drain() trigger based on OS write buffer size (bytes)
        - --tcp-bp-latency-ms    : if > 0, drain after this many ms with any pending bytes
        - --tcp-bp-poll-interval-ms: how often to check the buffer/time condition
        """
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--tcp-bind'):
            p.add_argument('--tcp-bind', default='::', help='TCP overlay bind address')
        if not _has('--tcp-own-port'):
            p.add_argument('--tcp-own-port', dest='tcp_own_port', type=int, default=8081, help='TCP overlay own port')
        if not _has('--tcp-peer'):
            p.add_argument('--tcp-peer', default=None, help='TCP peer IP/FQDN')
        if not _has('--tcp-peer-port'):
            p.add_argument('--tcp-peer-port', type=int, default=8081, help='TCP peer overlay port')

        if not _has('--tcp-bp-wbuf-threshold'):
            p.add_argument('--tcp-bp-wbuf-threshold', type=int, default=128 * 1024,
                        help='TCP overlay: write() buffer size threshold in bytes to signal drain (default 131072).')

        if not _has('--tcp-bp-latency-ms'):
            p.add_argument('--tcp-bp-latency-ms', type=int, default=300,
                        help='TCP overlay: if > 0, trigger drain after this latency (ms) whenever pending bytes exist.')

        if not _has('--tcp-bp-poll-interval-ms'):
            p.add_argument('--tcp-bp-poll-interval-ms', type=int, default=50,
                        help='TCP overlay: polling interval for time-based backpressure checks (ms; default 50).')
    @staticmethod
    def from_args(args: argparse.Namespace) -> "TcpStreamSession":
        s = TcpStreamSession(args)
        # Apply CLI tuning (safe even if attributes were pre-set in __init__)
        try:
            s._wbuf_threshold = int(getattr(args, 'tcp_bp_wbuf_threshold', s._wbuf_threshold))
        except Exception:
            pass
        # New: time-based knobs
        try:
            s._bp_latency_ms = int(getattr(args, 'tcp_bp_latency_ms', 0))
        except Exception:
            s._bp_latency_ms = 0
        try:
            s._bp_poll_interval_s = float(getattr(args, 'tcp_bp_poll_interval_ms', 50)) / 1000.0
        except Exception:
            s._bp_poll_interval_s = 0.05
        return s
    def __init__(self, args: argparse.Namespace):
        import zlib  # local import if not at top
        self._zlib = zlib

        self._args = args
        self._log = logging.getLogger("tcp_session")
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # tcp state
        self._server: Optional[asyncio.base_events.Server] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._rx_task: Optional[asyncio.Task] = None
        self._run_flag: bool = False

        # peer endpoints (client/server)
        self._listen_host, self._listen_port = _strip_brackets(self._args.tcp_bind), int(self._args.tcp_own_port)
        peer_info = _resolve_cli_peer(
            self._args,
            peer_attr="tcp_peer",
            peer_port_attr="tcp_peer_port",
            bind_host=self._listen_host,
            socktype=socket.SOCK_STREAM,
        )
        self._peer_tuple: Optional[Tuple[str, int]] = (
            (peer_info[0], peer_info[1]) if peer_info is not None else None
        )
        self._peer_host, self._peer_port = "", 0
        self._server_connected_evt: asyncio.Event = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1

        # framing
        self._LEN = struct.Struct(">I")

        # backpressure
        self._wbuf_threshold = 128 * 1024
        self._bp_evt: Optional[asyncio.Event] = None
        self._bp_task: Optional[asyncio.Task] = None

        # early buffer (APP frames only; store fully-framed bytes incl LEN+KIND)
        self._early_buf = bytearray()
        self._early_max = 1 * 1024 * 1024
        self._early_ttl = 3.0
        self._early_deadline = 0.0

        # counters (wire bytes)
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_crc32 = 0
        self._tx_crc32 = 0
        self._ctr_log_level = logging.DEBUG

        # RTT
        self._rtt = StreamRTT()
        self._rtt = StreamRTT(log=self._log.getChild("rtt"))
        self._rtt_rt = StreamRTTRuntime(self._rtt)

        # reconnect
        self._connecting_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None

        # cosmetics
        self._probe_id = f"{id(self)&0xFFFF:04x}"

        # overlay "connected" view is RTT-driven
        self._overlay_connected: bool = False

    # ---- ISession: callback wiring ----
    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set_cb = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect_cb = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb

    # ---- ISession: lifecycle ----
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._run_flag = True

        if self._peer_tuple:
            # CLIENT: proactive connect so RTT can flow immediately
            self._rtt_rt.attach(send_ping_fn=None, on_state_change=self._on_rtt_state_change)
            self._peer_host, self._peer_port = self._peer_tuple
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) start; CLIENT bind={self._listen_host}:{self._listen_port} peer={self._peer_tuple}")
            self._ensure_connect_once()
        else:
            # SERVER: listen and accept multiple overlay peers
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) start; SERVER bind={self._listen_host}:{self._listen_port}")
            async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                await self._on_accept(reader, writer)

            try:
                family = _listener_family_for_host(self._listen_host)
                self._server = await asyncio.start_server(_handle, host=self._listen_host, port=self._listen_port, family=family)
            except TypeError:
                self._server = await asyncio.start_server(_handle, host=self._listen_host, port=self._listen_port)
            sockets = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) server listening on {sockets}")

    async def stop(self) -> None:
        self._log.info(f"[TCP-SESSION] ({self._probe_id}) stopping")
        self._run_flag = False

        # tear down timers / tasks
        self._rtt_rt.detach()
        for t in (self._connecting_task, self._reconnect_task):
            if t: t.cancel()
        self._connecting_task = None
        self._reconnect_task = None

        for peer_id in list(self._server_peers.keys()):
            await self._close_server_peer(peer_id)
        self._server_connected_evt.clear()

        if self._bp_task:
            self._bp_task.cancel()
            self._bp_task = None
        self._bp_evt = None

        try:
            if self._rx_task: self._rx_task.cancel()
        except Exception: pass
        self._rx_task = None

        # close writer
        try:
            if self._writer:
                self._writer.close()
                aw = getattr(self._writer, "wait_closed", None)
                if callable(aw): await aw()
        except Exception: pass
        self._writer = None
        self._reader = None

        # close server
        try:
            if self._server:
                self._server.close()
                await self._server.wait_closed()
        except Exception: pass
        self._server = None

        # state off
        self._set_overlay_connected(False)

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if not self._peer_tuple:
            if self._server_peers:
                return True
            try:
                await asyncio.wait_for(self._server_connected_evt.wait(), timeout)
                return True
            except asyncio.TimeoutError:
                return False
        return await self._rtt_rt.wait_connected(timeout)

    def is_connected(self) -> bool:
        if not self._peer_tuple:
            return bool(self._server_peers)
        return self._rtt.is_connected()

    # ---- metrics surface for StatsBoard (RTT plumbing) ----
    def get_metrics(self) -> SessionMetrics:
        """
        Publish RTT numbers to the dashboard (transport-agnostic).
        Only RTT fields are populated for TCP; other congestion stats are n/a.
        """
        try:
            r = self._rtt
            return SessionMetrics(
                rtt_sample_ms=getattr(r, "rtt_sample_ms", None),
                rtt_est_ms=getattr(r, "rtt_est_ms", None),
                last_rtt_ok_ns=getattr(r, "last_rtt_ok_ns", None),
            )
        except Exception:
            return SessionMetrics()

    @staticmethod
    def _format_peer_label(host: Optional[object], port: Optional[object]) -> Optional[str]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return f"[{host_s}]:{port_i}" if ":" in host_s and not host_s.startswith("[") else f"{host_s}:{port_i}"
        except Exception:
            return None

    @staticmethod
    def _extract_quic_peer_addr(proto: Any) -> Tuple[Optional[str], Optional[int]]:
        try:
            quic = getattr(proto, "_quic", None)
            paths = getattr(quic, "_network_paths", None) if quic is not None else None
            if paths:
                addr = getattr(paths[0], "addr", None)
                if isinstance(addr, tuple) and len(addr) >= 2:
                    return str(addr[0]), int(addr[1])
        except Exception:
            pass
        try:
            transport = getattr(proto, "_transport", None)
            peer = transport.get_extra_info("peername") if transport is not None else None
            if isinstance(peer, tuple) and len(peer) >= 2:
                return str(peer[0]), int(peer[1])
        except Exception:
            pass
        return None, None

    def get_overlay_peers_snapshot(self) -> list[dict]:
        if self._peer_tuple:
            return [{
                "peer_id": 0,
                "connected": bool(self.is_connected()),
                "state": "connected" if self.is_connected() else "connecting",
                "peer": self._format_peer_label(self._peer_host, self._peer_port),
                "mux_chans": [],
                "rtt_est_ms": getattr(self._rtt, "rtt_est_ms", None),
            }]

        rows = [{
            "peer_id": -1,
            "connected": False,
            "state": "listening",
            "peer": None,
            "mux_chans": [],
            "rtt_est_ms": None,
            "listening": True,
        }]
        mux_by_peer: Dict[int, list[int]] = {}
        for mux_chan, mapped in self._server_chan_to_peer.items():
            try:
                peer_id, _peer_chan = mapped
                mux_by_peer.setdefault(int(peer_id), []).append(int(mux_chan))
            except Exception:
                continue
        for peer_id in sorted(self._server_peers.keys()):
            ctx = self._server_peers.get(peer_id, {})
            addr = ctx.get("addr") if isinstance(ctx, dict) else None
            host = addr[0] if isinstance(addr, tuple) and len(addr) >= 2 else None
            port = addr[1] if isinstance(addr, tuple) and len(addr) >= 2 else None
            rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
            rows.append({
                "peer_id": peer_id,
                "connected": bool(ctx.get("connected")) if isinstance(ctx, dict) else False,
                "state": "connected" if bool(ctx.get("connected")) else "connecting",
                "peer": self._format_peer_label(host, port),
                "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                "rtt_est_ms": getattr(rtt, "rtt_est_ms", None),
            })
        return rows

    def _alloc_server_peer_id(self) -> int:
        peer_id = self._server_next_peer_id
        while peer_id in self._server_peers:
            peer_id += 1
            if peer_id > 0xFFFF:
                peer_id = 1
        self._server_next_peer_id = 1 if peer_id >= 0xFFFF else (peer_id + 1)
        return peer_id

    def _alloc_server_mux_chan(self) -> int:
        chan = self._server_next_mux_chan
        while chan in self._server_chan_to_peer:
            chan += 2
            if chan > 0xFFFF:
                chan = 1
        self._server_next_mux_chan = 1 if chan >= 0xFFFF else (chan + 2)
        return chan

    def _rewrite_mux_chan_id(self, payload: bytes, new_chan: int) -> bytes:
        hdr = ChannelMux.MUX_HDR
        if len(payload) < hdr.size:
            return payload
        try:
            _old_chan, proto, counter, mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        return hdr.pack(new_chan, proto, counter, mtype, dlen) + payload[hdr.size:hdr.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        hdr = ChannelMux.MUX_HDR
        if len(payload) < hdr.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return payload
        if len(payload) < hdr.size + dlen:
            return payload
        key = (int(peer_id), int(peer_chan))
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = int(peer_chan)
            mapped = self._server_chan_to_peer.get(mux_chan)
            if mapped is not None and mapped != key:
                mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if int(key[0]) != int(peer_id):
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _resolve_server_send_target(self, payload: bytes, peer_id: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        hdr = ChannelMux.MUX_HDR
        if len(payload) < hdr.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = hdr.unpack(payload[:hdr.size])
        except Exception:
            return None
        if len(payload) < hdr.size + dlen:
            return None
        target_peer_id = int(peer_id) if peer_id is not None else None
        mapped = self._server_chan_to_peer.get(int(mux_chan))
        if target_peer_id is None and mapped is not None:
            target_peer_id = int(mapped[0])
        if target_peer_id is None:
            if len(self._server_peers) == 1:
                target_peer_id = next(iter(self._server_peers.keys()))
            else:
                return None
        target_ctx = self._server_peers.get(target_peer_id)
        if not target_ctx:
            return None
        peer_chan = int(mux_chan)
        if mapped is not None:
            if int(mapped[0]) != target_peer_id:
                return None
            peer_chan = int(mapped[1])
        else:
            key = (target_peer_id, int(mux_chan))
            self._server_peer_chan_to_mux[key] = int(mux_chan)
            self._server_chan_to_peer[int(mux_chan)] = key
        return target_peer_id, self._rewrite_mux_chan_id(payload, peer_chan) if peer_chan != int(mux_chan) else payload

    # ---- ISession: data path (APP) ----
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        if not self._peer_tuple:
            target = self._resolve_server_send_target(payload, peer_id=peer_id)
            if target is None:
                return 0
            target_peer_id, routed_payload = target
            ctx = self._server_peers.get(target_peer_id)
            writer = ctx.get("writer") if isinstance(ctx, dict) else None
            if writer is None:
                return 0
            wire = self._LEN.pack(len(routed_payload) + 1) + bytes([self._K_APP]) + routed_payload
            try:
                writer.write(wire)
                if ctx is not None:
                    self._bump_tx_for_ctx(ctx, wire)
                if self._on_peer_tx:
                    try: self._on_peer_tx(len(wire))
                    except Exception: pass
                return len(payload)
            except Exception as e:
                self._log.info(f"[TCP/TX] ({self._probe_id}) server write error peer_id={target_peer_id}: {e!r}")
                return 0
        frame = bytes([self._K_APP]) + payload
        body_len = len(frame)
        wire = self._LEN.pack(body_len) + frame

        if self._writer is None:
            # buffer APP frame until TCP exists
            self._buffer_early(wire)
            self._log.debug(f"[TCP/TX] ({self._probe_id}) early-buffer APP bytes={len(wire)} buf={len(self._early_buf)}")
            if self._peer_tuple:
                self._ensure_connect_once()
            return len(payload)

        try:
            self._writer.write(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            self._maybe_signal_bp()
            return len(payload)
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) write error: {e!r}")
            return 0

    # ---- accept/connect wiring ----
    async def _on_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        p = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")
        if not self._peer_tuple:
            peer_id = self._alloc_server_peer_id()
            rtt = StreamRTT(log=self._log.getChild(f"rtt.{peer_id}"))
            rtt_rt = StreamRTTRuntime(rtt)
            ctx = {
                "peer_id": peer_id,
                "reader": reader,
                "writer": writer,
                "addr": p if isinstance(p, tuple) and len(p) >= 2 else None,
                "connected": False,
                "rtt": rtt,
                "rtt_rt": rtt_rt,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_crc32": 0,
                "tx_crc32": 0,
                "rx_task": None,
            }
            self._server_peers[peer_id] = ctx
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) accept: peer_id={peer_id} local={sockname} peer={p}")
            try:
                if isinstance(p, tuple) and len(p) >= 2:
                    self._peer_host, self._peer_port = p[0], int(p[1])
                    if callable(self._on_peer_set_cb):
                        self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception:
                pass
            self._enable_os_keepalive(writer)
            rtt_rt.attach(
                send_ping_fn=lambda payload, _peer_id=peer_id: self._send_ping_frame_for_peer(_peer_id, payload),
                on_state_change=lambda connected, _peer_id=peer_id: self._on_state_change_for_peer(_peer_id, connected),
            )
            ctx["rx_task"] = self._loop.create_task(self._rx_pump_for_peer(peer_id))  # type: ignore[union-attr]
            self._update_server_overlay_connected()
            return

        # Replace any previous peer
        if self._writer is not None:
            try:
                self._writer.close()
                aw = getattr(self._writer, "wait_closed", None)
                if callable(aw): await aw()
            except Exception: pass

        self._reader, self._writer = reader, writer
        self._log.info(f"[TCP-SESSION] ({self._probe_id}) accept: local={sockname} peer={p}")
        try:
            if isinstance(p, tuple) and len(p) >= 2:
                self._peer_host, self._peer_port = p[0], int(p[1])
        except Exception: pass

        self._enable_os_keepalive(writer)
        self._reset_counters()
        self._ensure_bp_task()

        # give RTT runtime the send function (PING)
        self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)

        # start RX and flush any buffered APP frames
        self._rx_task = self._loop.create_task(self._rx_pump())
        self._flush_early()

    def _ensure_connect_once(self) -> None:
        if self._connecting_task is not None or not self._peer_tuple or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _connect():
            await self._connect_to(host, port)
        self._connecting_task = self._loop.create_task(_connect())

    def _start_reconnect_loop(self) -> None:
        if not self._peer_tuple or self._reconnect_task is not None or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _reconnect():
            delay = 0.5
            while self._run_flag:
                # If TCP writer exists, exit (RTT runtime will flip overlay state)
                if self._writer is not None:
                    return
                await self._connect_to(host, port)
                if self._writer is not None:
                    return
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return
                delay = min(delay * 2.0, 10.0)
        self._reconnect_task = self._loop.create_task(_reconnect())

    def _enable_os_keepalive(self, writer: asyncio.StreamWriter) -> None:
        try:
            transport = writer.transport  # type: ignore[attr-defined]
            sock = transport.get_extra_info("socket") if transport else None
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self._log.info(f"[TCP-SESSION] ({self._probe_id}) SO_KEEPALIVE=1 set")
        except Exception as e:
            self._log.debug(f"[TCP-SESSION] ({self._probe_id}) keepalive sockopt failed: {e!r}")

    async def _connect_to(self, host: str, port: int) -> None:
        if not self._run_flag:
            return
        try:
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) connecting to {host}:{port}")
            t0 = time.perf_counter()
            transport, _ = await loop.create_connection(lambda: protocol, host=host, port=int(port))
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            dt = (time.perf_counter() - t0) * 1000.0
            laddr = transport.get_extra_info("sockname")
            raddr = transport.get_extra_info("peername")
            self._log.info(f"[TCP-SESSION] ({self._probe_id}) connected in {dt:.1f} ms local={laddr} peer={raddr}")

            self._reader, self._writer = reader, writer
            self._peer_host, self._peer_port = host, int(port)

            self._enable_os_keepalive(writer)
            self._reset_counters()
            self._ensure_bp_task()

            # attach RTT sender and start RX; buffered APP gets flushed
            self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)
            self._rx_task = loop.create_task(self._rx_pump())
            self._flush_early()
        except Exception as e:
            self._log.warning(f"[TCP-SESSION] ({self._probe_id}) connect failed to {host}:{port}: {e!r}")
        finally:
            self._connecting_task = None

    # ---- RX/TX internals ----
    def _reset_counters(self) -> None:
        self._rx_bytes = self._tx_bytes = 0
        self._rx_crc32 = self._tx_crc32 = 0
        self._log.debug(f"[TCP/CTR] ({self._probe_id}) reset (RX=0 CRC=0x00000000, TX=0 CRC=0x00000000)")

    def _log_counters(self, direction: str) -> None:
        self._log.log(
            self._ctr_log_level,
            f"[TCP/CTR] ({self._probe_id}) {direction} "
            f"TX={self._tx_bytes} CRC32_TX=0x{self._tx_crc32:08x}  "
            f"RX={self._rx_bytes} CRC32_RX=0x{self._rx_crc32:08x}"
        )

    def _bump_tx(self, data: bytes) -> None:
        self._tx_bytes += len(data)
        self._tx_crc32 = self._zlib.crc32(data, self._tx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _bump_rx(self, data: bytes) -> None:
        self._rx_bytes += len(data)
        self._rx_crc32 = self._zlib.crc32(data, self._rx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _ensure_bp_task(self) -> None:
        """
        Ensure a single background drain() worker exists.

        Triggers:
        1) Size-based: if transport.get_write_buffer_size() >= self._wbuf_threshold
        2) Time-based: if _bp_latency_ms > 0 and there have been pending bytes
            for at least _bp_latency_ms; polled every _bp_poll_interval_s.

        Notes:
        - Works even if _bp_* attributes were not set in __init__ (defaults here).
        - Stops automatically when writer is gone or task is cancelled on stop().
        """
        if self._bp_task or not self._writer:
            return

        # Event used by size-based path (_maybe_signal_bp)
        self._bp_evt = asyncio.Event()

        # Safe defaults if caller didn't configure
        wbuf_threshold = int(getattr(self, "_wbuf_threshold", 128 * 1024))
        latency_ms = int(getattr(self, "_bp_latency_ms", 0))
        poll_s = float(getattr(self, "_bp_poll_interval_s", 0.05))
        latency_ns = int(max(0, latency_ms) * 1e6)

        async def _bp():
            try:
                # Track how long we've had *any* pending bytes.
                nonzero_since_ns = 0
                while self._run_flag and self._writer:
                    # Wait for either a size-based signal OR a short timeout to poll time-based condition
                    try:
                        await asyncio.wait_for(self._bp_evt.wait(), timeout=poll_s)
                        self._bp_evt.clear()
                    except asyncio.TimeoutError:
                        pass  # fall through to polling checks

                    writer = self._writer
                    if not writer:
                        break

                    transport = getattr(writer, "transport", None)  # type: ignore[attr-defined]
                    if not transport:
                        break

                    try:
                        wbs = transport.get_write_buffer_size()
                    except Exception:
                        wbs = 0

                    now_ns = time.monotonic_ns()

                    # Track the time window during which wbs > 0
                    if wbs > 0:
                        if nonzero_since_ns == 0:
                            nonzero_since_ns = now_ns
                    else:
                        nonzero_since_ns = 0  # reset when buffer empties

                    # Should we drain now?
                    do_drain = False
                    reason = ""
                    if wbs >= wbuf_threshold:
                        do_drain = True
                        reason = f"wbuf={wbs} thr={wbuf_threshold}"
                    elif latency_ns > 0 and nonzero_since_ns and (now_ns - nonzero_since_ns) >= latency_ns:
                        do_drain = True
                        waited_ms = (now_ns - nonzero_since_ns) / 1e6
                        reason = f"latency_ms={waited_ms:.1f} (>= {latency_ms})"

                    if do_drain:
                        try:
                            t0 = time.perf_counter()
                            await writer.drain()
                            dt = (time.perf_counter() - t0) * 1000.0
                            self._log.debug(f"[TCP/BP] ({self._probe_id}) drain() done in {dt:.2f} ms; reason: {reason}")
                        except Exception as e:
                            self._log.info(f"[TCP/BP] ({self._probe_id}) drain failed: {e!r}")
                            break

            except asyncio.CancelledError:
                return

        self._bp_task = self._loop.create_task(_bp())
        
    def _maybe_signal_bp(self) -> None:
        """
        Size-based path: if OS write buffer crosses threshold, poke the drain worker.
        Time-based path is handled inside _ensure_bp_task polling loop.
        """
        try:
            if not self._writer:
                return
            transport = self._writer.transport  # type: ignore[attr-defined]
            if not transport:
                return
            wbs = transport.get_write_buffer_size()
            thr = int(getattr(self, "_wbuf_threshold", 128 * 1024))
            if wbs >= thr and self._bp_evt:
                self._log.debug(f"[TCP/BP] ({self._probe_id}) signal drain; wbuf={wbs} thr={thr}")
                self._bp_evt.set()
        except Exception:
            pass

    def _buffer_early(self, wire_frame: bytes) -> None:
        now = time.time()
        if self._early_deadline and now > self._early_deadline:
            self._log.info(f"[TCP/TX] ({self._probe_id}) early-buf TTL expired; discarding {len(self._early_buf)}B")
            self._early_buf.clear()
        self._early_deadline = now + self._early_ttl

        over = (len(self._early_buf) + len(wire_frame)) - self._early_max
        if over > 0:
            drop = min(over, len(self._early_buf))
            if drop:
                del self._early_buf[:drop]
                self._log.info(f"[TCP/TX] ({self._probe_id}) early-buf capped: dropped={drop} keep={len(self._early_buf)} cap={self._early_max}")

        self._early_buf += wire_frame

    def _flush_early(self) -> None:
        if not self._early_buf or not self._writer:
            return
        try:
            n = len(self._early_buf)
            self._log.info(f"[TCP/TX] ({self._probe_id}) flushing early-buf bytes={n}")
            self._writer.write(self._early_buf)
            self._bump_tx(self._early_buf)
            self._maybe_signal_bp()
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) flush error: {e!r}")
        finally:
            self._early_buf.clear()
            self._early_deadline = 0.0

    def _send_ping_frame(self, ping_payload: bytes) -> None:
        """
        Called by StreamRTTRuntime. Sends a PING control frame if TCP writer exists.
        """
        if not self._writer:
            return
        body = bytes([self._K_PING]) + ping_payload
        wire = self._LEN.pack(len(body)) + body
        try:
            self._writer.write(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            self._maybe_signal_bp()
            self._log.debug(f"[TCP/TX] ({self._probe_id}) PING")
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PING write error: {e!r}")

    def _send_pong_frame(self, echo_tx_ns: int) -> None:
        if not self._writer:
            return
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        try:
            self._writer.write(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            self._maybe_signal_bp()
            self._log.debug(f"[TCP/TX] ({self._probe_id}) PONG")
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PONG write error: {e!r}")

    def _bump_tx_for_ctx(self, ctx: dict, data: bytes) -> None:
        ctx["tx_bytes"] = int(ctx.get("tx_bytes", 0) or 0) + len(data)
        ctx["tx_crc32"] = self._zlib.crc32(data, int(ctx.get("tx_crc32", 0) or 0)) & 0xFFFFFFFF

    def _bump_rx_for_ctx(self, ctx: dict, data: bytes) -> None:
        ctx["rx_bytes"] = int(ctx.get("rx_bytes", 0) or 0) + len(data)
        ctx["rx_crc32"] = self._zlib.crc32(data, int(ctx.get("rx_crc32", 0) or 0)) & 0xFFFFFFFF

    def _send_ping_frame_for_peer(self, peer_id: int, ping_payload: bytes) -> None:
        ctx = self._server_peers.get(peer_id)
        writer = ctx.get("writer") if isinstance(ctx, dict) else None
        if writer is None:
            return
        body = bytes([self._K_PING]) + ping_payload
        wire = self._LEN.pack(len(body)) + body
        try:
            writer.write(wire)
            self._bump_tx_for_ctx(ctx, wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PING write error peer_id={peer_id}: {e!r}")

    def _send_pong_frame_for_peer(self, peer_id: int, echo_tx_ns: int) -> None:
        ctx = self._server_peers.get(peer_id)
        writer = ctx.get("writer") if isinstance(ctx, dict) else None
        rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
        if writer is None or rtt is None:
            return
        body = bytes([self._K_PONG]) + rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        try:
            writer.write(wire)
            self._bump_tx_for_ctx(ctx, wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
        except Exception as e:
            self._log.info(f"[TCP/TX] ({self._probe_id}) PONG write error peer_id={peer_id}: {e!r}")

    async def _rx_pump(self) -> None:
        self._log.debug(f"[TCP/RX] ({self._probe_id}) pump start")
        try:
            while True:
                # read 4B length
                hdr = await self._reader.readexactly(self._LEN.size)  # type: ignore[arg-type]
                if not hdr:
                    self._log.info(f"[TCP/RX] ({self._probe_id}) EOF on length")
                    break
                self._bump_rx(hdr)
                (n,) = self._LEN.unpack(hdr)
                if n <= 0:
                    continue

                body = await self._reader.readexactly(n)  # type: ignore[arg-type]
                self._bump_rx(body)
                kind = body[0]
                payload = body[1:]

                # per-direction meters
                if self._on_peer_rx:
                    try: self._on_peer_rx(len(hdr) + len(body))
                    except Exception: pass

                # demux kinds
                if kind == self._K_APP:
                    if self._on_app_from_peer_bytes:
                        try: self._on_app_from_peer_bytes(len(payload))
                        except Exception: pass
                    if callable(self._on_app):
                        try: self._on_app(payload)
                        except Exception as e:
                            self._log.debug(f"[TCP/RX] ({self._probe_id}) app callback err: {e!r}")
                elif kind == self._K_PING:
                    # payload must be 16 bytes (tx_ns, echo_ns)
                    if len(payload) >= 16:
                        tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])
                        self._log.debug(f"[TCP/RX] PING recv {tx_ns} {echo_ns}")                        
                        self._rtt.on_ping_received(tx_ns)
                        if echo_ns:
                            # update our RTT immediately as a courtesy (optional)
                            self._rtt.on_pong_received(echo_ns)
                        # immediate PONG reflecting their tx_ns
                        self._send_pong_frame(tx_ns)
                    else:
                        self._log.debug(f"[TCP/RX] ({self._probe_id}) malformed PING len={len(payload)}")
                elif kind == self._K_PONG:
                    self._log.debug(f"[TCP/RX] PONG recv {len(payload)}")
                    if len(payload) >= 8:
                        (echo_tx_ns,) = struct.unpack(">Q", payload[:8])
                        self._log.debug(f"[TCP/RX] PONG recv {echo_tx_ns}")                        
                        self._rtt.on_pong_received(echo_tx_ns)
                        # state transition handled by runtime tick; this makes it near-immediate
                        if self._on_state:
                            # nudge UI quickly if this is the first success
                            was = self._overlay_connected
                            now = self._rtt.is_connected()
                            if now != was:
                                self._set_overlay_connected(now)
                    else:
                        self._log.debug(f"[TCP/RX] ({self._probe_id}) malformed PONG len={len(payload)}")
                else:
                    self._log.debug(f"[TCP/RX] ({self._probe_id}) unknown KIND=0x{kind:02x}, n={n}")
        except asyncio.IncompleteReadError as e:
            self._log.info(f"[TCP/RX] ({self._probe_id}) incomplete-read: expected={getattr(e,'expected',-1)} partial={len(getattr(e,'partial',b''))}")
        except asyncio.CancelledError:
            self._log.debug(f"[TCP/RX] ({self._probe_id}) cancelled")
            return
        except Exception as e:
            self._log.info(f"[TCP/RX] ({self._probe_id}) pump error: {e!r}")
        finally:
            # writer cleanup and reconnect policy
            try:
                if self._writer:
                    self._writer.close()
                    aw = getattr(self._writer, "wait_closed", None)
                    if callable(aw): await aw()
            except Exception: pass
            self._writer = None
            self._reader = None

            # overlay becomes disconnected (RTT view)
            self._set_overlay_connected(False)

            # client: attempt reconnect
            if self._peer_tuple:
                self._start_reconnect_loop()

            self._log.debug(f"[TCP/RX] ({self._probe_id}) pump stop")

    async def _rx_pump_for_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.get(peer_id)
        if not ctx:
            return
        reader = ctx.get("reader")
        writer = ctx.get("writer")
        rtt = ctx.get("rtt")
        self._log.debug(f"[TCP/RX] ({self._probe_id}) server pump start peer_id={peer_id}")
        try:
            while True:
                hdr = await reader.readexactly(self._LEN.size)
                if not hdr:
                    break
                self._bump_rx_for_ctx(ctx, hdr)
                (n,) = self._LEN.unpack(hdr)
                if n <= 0:
                    continue
                body = await reader.readexactly(n)
                self._bump_rx_for_ctx(ctx, body)
                kind = body[0]
                payload = body[1:]

                if self._on_peer_rx:
                    try: self._on_peer_rx(len(hdr) + len(body))
                    except Exception: pass

                if kind == self._K_APP:
                    if self._on_app_from_peer_bytes:
                        try: self._on_app_from_peer_bytes(len(payload))
                        except Exception: pass
                    if callable(self._on_app):
                        try:
                            rewritten = self._server_rewrite_inbound_app(peer_id, payload)
                            try: self._on_app(rewritten, peer_id=peer_id)
                            except TypeError: self._on_app(rewritten)
                        except Exception as e:
                            self._log.debug(f"[TCP/RX] ({self._probe_id}) server app callback err peer_id={peer_id}: {e!r}")
                elif kind == self._K_PING:
                    if len(payload) >= 16 and rtt is not None:
                        tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])
                        rtt.on_ping_received(tx_ns)
                        if echo_ns:
                            rtt.on_pong_received(echo_ns)
                        self._send_pong_frame_for_peer(peer_id, tx_ns)
                elif kind == self._K_PONG:
                    if len(payload) >= 8 and rtt is not None:
                        (echo_tx_ns,) = struct.unpack(">Q", payload[:8])
                        rtt.on_pong_received(echo_tx_ns)
        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            self._log.info(f"[TCP/RX] ({self._probe_id}) server pump error peer_id={peer_id}: {e!r}")
        finally:
            try:
                if writer:
                    writer.close()
                    aw = getattr(writer, "wait_closed", None)
                    if callable(aw): await aw()
            except Exception:
                pass
            await self._close_server_peer(peer_id)
            self._log.debug(f"[TCP/RX] ({self._probe_id}) server pump stop peer_id={peer_id}")

    # ---- overlay state (RTT-driven) ----
    def _on_rtt_state_change(self, connected: bool) -> None:
        # Called by RTT runtime tick
        prev = self._overlay_connected
        if connected != prev:
            self._log.info(f"[WS/GUARD] ({self._probe_id}) RTT state flip: {'CONNECTED' if connected else 'DISCONNECTED'}")
        self._set_overlay_connected(connected)


    def _set_overlay_connected(self, v: bool) -> None:
        if self._overlay_connected == v:
            return
        self._overlay_connected = v
        self._log.info(f"[TCP-SESSION] ({self._probe_id}) overlay -> {'CONNECTED' if v else 'DISCONNECTED'} (RTT)")
        if v and callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass
        if callable(self._on_state):
            try: self._on_state(v)
            except Exception: pass

    def _on_state_change_for_peer(self, peer_id: int, connected: bool) -> None:
        ctx = self._server_peers.get(peer_id)
        if ctx is not None:
            ctx["connected"] = bool(connected)
        self._update_server_overlay_connected()

    def _update_server_overlay_connected(self) -> None:
        connected = bool(self._server_peers)
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        self._set_overlay_connected(connected)

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        self._server_unregister_peer_channels(peer_id)
        rtt_rt = ctx.get("rtt_rt")
        if rtt_rt is not None:
            with contextlib.suppress(Exception):
                rtt_rt.detach()
        rx_task = ctx.get("rx_task")
        if rx_task and rx_task is not asyncio.current_task():
            rx_task.cancel()
        writer = ctx.get("writer")
        if writer is self._writer:
            self._writer = None
            self._reader = None
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception:
                pass
        try:
            if writer:
                writer.close()
                aw = getattr(writer, "wait_closed", None)
                if callable(aw): await aw()
        except Exception:
            pass
        self._update_server_overlay_connected()


# -----------------------------------------------------------------------------

# --- QUIC overlay -------------------------------------------------------------
# Requires: pip install aioquic
import ssl
import asyncio
import struct
import time
import logging
from typing import Optional, Callable, Tuple


def _load_aioquic_symbols() -> Dict[str, Any]:
    from aioquic.asyncio import serve as quic_serve, connect as quic_connect, QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import (
        StreamDataReceived,
        HandshakeCompleted,
        ConnectionTerminated,
        ProtocolNegotiated,
    )
    return {
        "quic_serve": quic_serve,
        "quic_connect": quic_connect,
        "QuicConnectionProtocol": QuicConnectionProtocol,
        "QuicConfiguration": QuicConfiguration,
        "StreamDataReceived": StreamDataReceived,
        "HandshakeCompleted": HandshakeCompleted,
        "ConnectionTerminated": ConnectionTerminated,
        "ProtocolNegotiated": ProtocolNegotiated,
    }

class QuicSession(ISession):
    """
    Overlay Session over one QUIC connection + one bidirectional stream.

    Framing (same as TcpStreamSession):
        frame := LEN(4) + KIND(1) + BYTES...
        KIND=0x00 -> APP
        KIND=0x01 -> PING (payload: Q tx_ns, Q echo_ns)
        KIND=0x02 -> PONG (payload: Q echo_tx_ns)

    Features:
      - Server & client roles via --quic-bind/--quic-own-port and --quic-peer/--quic-peer-port
      - TLS via aioquic (server: --quic-cert/--quic-key; client: --quic-insecure for labs)
      - Auto-reconnect (client) with backoff
      - RTT estimation (StreamRTT/StreamRTTRuntime) drives overlay 'connected'
      - Per-connection counters + running CRC32 (LEN+KIND+payload)
      - Early buffer for APP frames before QUIC stream exists
      - Structured DEBUG logging (parity with TCP/WS style)
    """

    _K_APP  = 0x00
    _K_PING = 0x01
    _K_PONG = 0x02

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False

        if not _has('--quic-bind'):
            p.add_argument('--quic-bind', default='::', help='QUIC overlay bind address')
        if not _has('--quic-own-port'):
            p.add_argument('--quic-own-port', dest='quic_own_port', type=int, default=443, help='QUIC overlay own port')
        if not _has('--quic-peer'):
            p.add_argument('--quic-peer', default=None, help='QUIC peer IP/FQDN')
        if not _has('--quic-peer-port'):
            p.add_argument('--quic-peer-port', type=int, default=443, help='QUIC peer overlay port')

        if not _has('--quic-alpn'):
            p.add_argument('--quic-alpn', default='hq-29',
                           help="ALPN protocol ID (default hq-29)")
        if not _has('--quic-cert'):
            p.add_argument('--quic-cert', default=None,
                           help='Server certificate file (PEM)')
        if not _has('--quic-key'):
            p.add_argument('--quic-key', default=None,
                           help='Server private key file (PEM)')
        if not _has('--quic-insecure'):
            p.add_argument('--quic-insecure', action='store_true', default=False,
                           help='Client: disable certificate verification (TEST ONLY)')
        if not _has('--quic-max-size'):
            p.add_argument('--quic-max-size', type=int, default=65535,
                           help='Maximum app message size accepted/sent (default 65535).')

    @staticmethod
    def from_args(args: argparse.Namespace) -> "QuicSession":
        return QuicSession(args)

    def __init__(self, args: argparse.Namespace):
        if importlib.util.find_spec("aioquic") is None:
            raise RuntimeError(
                "overlay_transport=quic requires optional dependency 'aioquic'. "
                "Install it with: pip install aioquic"
            )
        aioquic = _load_aioquic_symbols()

        import zlib as _z
        self._args = args
        self._log  = logging.getLogger("quic_session")
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # Addressing / role
        self._listen_host, self._listen_port = _strip_brackets(args.quic_bind), int(args.quic_own_port)
        self._peer_name_host = _strip_brackets(getattr(args, "quic_peer", None) or "")
        self._peer_name_port = int(getattr(args, "quic_peer_port", 0) or 0)
        peer_info = _resolve_cli_peer(
            args,
            peer_attr="quic_peer",
            peer_port_attr="quic_peer_port",
            bind_host=self._listen_host,
            socktype=socket.SOCK_DGRAM,
        )
        self._peer_tuple: Optional[Tuple[str, int]] = (
            (peer_info[0], peer_info[1]) if peer_info is not None else None
        )
        self._peer_host, self._peer_port = "", 0

        # AIOQUIC handles
        self._server = None
        self._proto: Optional[Any] = None
        self._quic = None
        self._stream_id: Optional[int] = None
        self._rx_task: Optional[asyncio.Task] = None
        self._connecting_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._run_flag: bool = False
        self._server_connected_evt = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_proto_to_peer_id: Dict[int, int] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1
        self._quic_serve = aioquic["quic_serve"]
        self._quic_connect = aioquic["quic_connect"]
        self._quic_protocol_cls = aioquic["QuicConnectionProtocol"]
        self._quic_configuration_cls = aioquic["QuicConfiguration"]
        self._quic_event_stream_data = aioquic["StreamDataReceived"]
        self._quic_event_handshake = aioquic["HandshakeCompleted"]
        self._quic_event_terminated = aioquic["ConnectionTerminated"]
        self._quic_event_negotiated = aioquic["ProtocolNegotiated"]

        # Framing / buffers
        self._LEN = struct.Struct(">I")
        self._rx_buf = bytearray()
        self._early_buf = bytearray()        # fully-framed (LEN+KIND+payload)
        self._early_max = 1 * 1024 * 1024
        self._early_ttl = 3.0
        self._early_deadline = 0.0
        self._max_app = int(getattr(args, "quic_max_size", 65535))

        # Counters
        self._z = _z
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_crc32 = 0
        self._tx_crc32 = 0
        self._ctr_log_level = logging.DEBUG

        # RTT runtime
        self._rtt = StreamRTT(log=self._log.getChild("rtt"))
        self._rtt_rt = StreamRTTRuntime(self._rtt)
        self._overlay_connected: bool = False
        self._probe_id = f"{id(self)&0xFFFF:04x}"

        # TLS/ALPN
        self._alpn = getattr(args, "quic_alpn", "hq-29") or "hq-29"
        self._server_cert = getattr(args, "quic_cert", None)
        self._server_key  = getattr(args, "quic_key", None)
        self._client_insecure = bool(getattr(args, "quic_insecure", False))

    # ---- ISession callbacks ----
    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set_cb = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect_cb = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb

    # ---- lifecycle ----
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._run_flag = True
        if self._peer_tuple:
            # Attach RTT driver; we’ll attach send_pings once we have a stream
            self._rtt_rt.attach(send_ping_fn=None, on_state_change=self._on_rtt_state_change)
            # CLIENT
            self._peer_host = self._peer_name_host or self._peer_tuple[0]
            self._peer_port = self._peer_name_port or self._peer_tuple[1]
            self._log.info(
                f"[QUIC-SESSION] ({self._probe_id}) start; CLIENT -> "
                f"{self._peer_host}:{self._peer_port} resolved={self._peer_tuple} "
                f"alpn={self._alpn} insecure={self._client_insecure}"
            )
            self._ensure_connect_once()
        else:
            # SERVER
            self._log.info(f"[QUIC-SESSION] ({self._probe_id}) start; SERVER bind={self._listen_host}:{self._listen_port} alpn={self._alpn}")
            await self._start_server()

    async def stop(self) -> None:
        self._log.info(f"[QUIC-SESSION] ({self._probe_id}) stopping")
        self._run_flag = False
        if self._peer_tuple:
            self._rtt_rt.detach()
        for t in (self._connecting_task, self._reconnect_task):
            if t: t.cancel()
        self._connecting_task = None
        self._reconnect_task = None
        try:
            if self._rx_task: self._rx_task.cancel()
        except Exception: pass
        self._rx_task = None

        if not self._peer_tuple:
            for peer_id in list(self._server_peers.keys()):
                await self._close_server_peer(peer_id)
        else:
            # close connection (client role)
            try:
                if self._proto:
                    self._proto.close()
            except Exception:
                pass
            self._proto = None
            self._quic = None
            self._stream_id = None

        # close server (server role)
        try:
            if self._server:
                self._server.close()
                await self._server.wait_closed()
        except Exception:
            pass
        self._server = None

        self._set_overlay_connected(False)

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if not self._peer_tuple:
            if self._server_peers:
                return True
            try:
                await asyncio.wait_for(self._server_connected_evt.wait(), timeout)
                return True
            except asyncio.TimeoutError:
                return False
        return await self._rtt_rt.wait_connected(timeout)

    def is_connected(self) -> bool:
        if not self._peer_tuple:
            return bool(self._server_peers)
        return self._rtt.is_connected()

    # ---- metrics (for dashboard) ----
    def get_metrics(self) -> SessionMetrics:
        try:
            r = self._rtt
            return SessionMetrics(
                rtt_sample_ms=getattr(r, "rtt_sample_ms", None),
                rtt_est_ms=getattr(r, "rtt_est_ms", None),
                last_rtt_ok_ns=getattr(r, "last_rtt_ok_ns", None),
            )
        except Exception:
            return SessionMetrics()

    @staticmethod
    def _format_peer_label(host: Optional[object], port: Optional[object]) -> Optional[str]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return f"[{host_s}]:{port_i}" if ":" in host_s and not host_s.startswith("[") else f"{host_s}:{port_i}"
        except Exception:
            return None

    @staticmethod
    def _extract_quic_peer_addr(proto: Any) -> Tuple[Optional[str], Optional[int]]:
        try:
            quic = getattr(proto, "_quic", None)
            paths = getattr(quic, "_network_paths", None) if quic is not None else None
            if paths:
                addr = getattr(paths[0], "addr", None)
                if isinstance(addr, tuple) and len(addr) >= 2:
                    return str(addr[0]), int(addr[1])
        except Exception:
            pass
        try:
            transport = getattr(proto, "_transport", None)
            peer = transport.get_extra_info("peername") if transport is not None else None
            if isinstance(peer, tuple) and len(peer) >= 2:
                return str(peer[0]), int(peer[1])
        except Exception:
            pass
        return None, None

    def get_overlay_peers_snapshot(self) -> list[dict]:
        if self._peer_tuple:
            return [{
                "peer_id": 0,
                "connected": bool(self.is_connected()),
                "state": "connected" if self.is_connected() else "connecting",
                "peer": self._format_peer_label(self._peer_host, self._peer_port),
                "mux_chans": [],
                "rtt_est_ms": getattr(self._rtt, "rtt_est_ms", None),
            }]

        rows = [{
            "peer_id": -1,
            "connected": False,
            "state": "listening",
            "peer": None,
            "mux_chans": [],
            "rtt_est_ms": None,
            "listening": True,
        }]
        mux_by_peer: Dict[int, list[int]] = {}
        for mux_chan, mapped in self._server_chan_to_peer.items():
            try:
                peer_id, _peer_chan = mapped
                mux_by_peer.setdefault(int(peer_id), []).append(int(mux_chan))
            except Exception:
                continue

        peer_ids: set[int] = set(int(p) for p in self._server_peers.keys())
        peer_ids.update(int(p) for p in mux_by_peer.keys())
        for peer_id in sorted(peer_ids):
            ctx = self._server_peers.get(peer_id, {})
            host = ctx.get("peer_host") if isinstance(ctx, dict) else None
            port = ctx.get("peer_port") if isinstance(ctx, dict) else None
            if (host is None or port is None) and isinstance(ctx, dict):
                proto = ctx.get("proto")
                host, port = self._extract_quic_peer_addr(proto)
                if host is not None and port is not None:
                    ctx["peer_host"], ctx["peer_port"] = host, port
            peer_label = self._format_peer_label(host, port)
            rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
            rows.append({
                "peer_id": peer_id,
                "connected": bool(peer_id in self._server_peers),
                "state": "connected" if peer_id in self._server_peers else "connecting",
                "peer": peer_label,
                "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                "rtt_est_ms": getattr(rtt, "rtt_est_ms", None),
            })
        return rows

    def _alloc_server_peer_id(self) -> int:
        peer_id = self._server_next_peer_id
        while peer_id in self._server_peers:
            peer_id += 1
            if peer_id > 0xFFFF:
                peer_id = 1
        self._server_next_peer_id = 1 if peer_id >= 0xFFFF else (peer_id + 1)
        return peer_id

    def _alloc_server_mux_chan(self) -> int:
        chan = self._server_next_mux_chan
        while chan in self._server_chan_to_peer:
            chan += 2
            if chan > 0xFFFF:
                chan = 1
        self._server_next_mux_chan = 1 if chan >= 0xFFFF else (chan + 2)
        return chan

    def _rewrite_mux_chan_id(self, payload: bytes, new_chan: int) -> bytes:
        mux_hdr = struct.Struct(">HBHBH")
        if len(payload) < mux_hdr.size:
            return payload
        try:
            _old_chan, proto, counter, mtype, dlen = mux_hdr.unpack(payload[:mux_hdr.size])
        except Exception:
            return payload
        if len(payload) < mux_hdr.size + dlen:
            return payload
        return mux_hdr.pack(new_chan, proto, counter, mtype, dlen) + payload[mux_hdr.size:mux_hdr.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        mux_hdr = struct.Struct(">HBHBH")
        if len(payload) < mux_hdr.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = mux_hdr.unpack(payload[:mux_hdr.size])
        except Exception:
            return payload
        if len(payload) < mux_hdr.size + dlen:
            return payload
        key = (int(peer_id), int(peer_chan))
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = int(peer_chan)
            mapped = self._server_chan_to_peer.get(mux_chan)
            if mapped is not None and mapped != key:
                mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if int(key[0]) != int(peer_id):
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _resolve_server_send_target(self, payload: bytes, peer_id: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        mux_hdr = struct.Struct(">HBHBH")
        if len(payload) < mux_hdr.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = mux_hdr.unpack(payload[:mux_hdr.size])
        except Exception:
            return None
        if len(payload) < mux_hdr.size + dlen:
            return None
        target_peer_id = int(peer_id) if peer_id is not None else None
        mapped = self._server_chan_to_peer.get(int(mux_chan))
        if target_peer_id is None and mapped is not None:
            target_peer_id = int(mapped[0])
        if target_peer_id is None:
            if len(self._server_peers) == 1:
                target_peer_id = next(iter(self._server_peers.keys()))
            else:
                return None
        target_ctx = self._server_peers.get(target_peer_id)
        if not target_ctx:
            return None
        peer_chan = int(mux_chan)
        if mapped is not None:
            if int(mapped[0]) != target_peer_id:
                return None
            peer_chan = int(mapped[1])
        else:
            key = (target_peer_id, int(mux_chan))
            self._server_peer_chan_to_mux[key] = int(mux_chan)
            self._server_chan_to_peer[int(mux_chan)] = key
        return target_peer_id, self._rewrite_mux_chan_id(payload, peer_chan) if peer_chan != int(mux_chan) else payload

    def _update_server_overlay_connected(self) -> None:
        connected = bool(self._server_peers)
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        self._set_overlay_connected(connected)

    # ---- data path (APP) ----
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        if len(payload) > self._max_app:
            self._log.error(f"[QUIC/TX] ({self._probe_id}) app payload too large ({len(payload)} > {self._max_app}); drop")
            return 0
        if not self._peer_tuple:
            target = self._resolve_server_send_target(payload, peer_id=peer_id)
            if target is None:
                self._log.debug(f"[QUIC/TX] ({self._probe_id}) drop unroutable server APP len={len(payload)} peer_id={peer_id}")
                return 0
            target_peer_id, routed_payload = target
            ctx = self._server_peers.get(target_peer_id)
            if not ctx:
                return 0
            wire = self._LEN.pack(len(routed_payload) + 1) + bytes([self._K_APP]) + routed_payload
            if not self._send_wire_ctx(ctx, wire):
                return 0
            return len(payload)
        body = bytes([self._K_APP]) + payload
        wire = self._LEN.pack(len(body)) + body

        if not self._quic or self._stream_id is None:
            self._buffer_early(wire)
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) early-buffer APP bytes={len(wire)} buf={len(self._early_buf)}")
            if self._peer_tuple:
                self._ensure_connect_once()
            return len(payload)

        try:
            self._send_wire(wire)
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            return len(payload)
        except Exception as e:
            self._log.info(f"[QUIC/TX] ({self._probe_id}) write error: {e!r}")
            return 0

    # ---- server/client wiring ----
    async def _start_server(self) -> None:
        """
        Server role: listen for QUIC connections and adopt the connection once
        the TLS handshake completes. Compatible with aioquic variants that do
        NOT expose a '.sockets' attribute on the returned server object.
        """
        if not self._server_cert or not self._server_key:
            raise RuntimeError("QUIC server requires --quic-cert and --quic-key (PEM files)")

        cfg = self._quic_configuration_cls(is_client=False, alpn_protocols=[self._alpn])
        cfg.load_cert_chain(self._server_cert, self._server_key)

        parent = self

        class _Proto(self._quic_protocol_cls):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._parent = parent
                self._accepted = False  # adopt only once per connection

            def quic_event_received(self, event):
                # On first completed TLS handshake, adopt this connection at the session layer.
                if isinstance(event, self._parent._quic_event_handshake) and not self._accepted:
                    self._accepted = True
                    self._parent._on_accept(self)
                # Forward all events to the session’s demux
                self._parent._on_quic_event(self, event)

        # Start listening
        self._server = await self._quic_serve(
            self._listen_host,
            self._listen_port,
            configuration=cfg,
            create_protocol=_Proto,
        )

        # Log a "we are listening" message that never touches .sockets
        # Try to extract addresses from transports (if present); otherwise print host:port.
        try:
            transports_attr = getattr(self._server, "transports", None)
            if transports_attr:
                addrs = []
                for tr in transports_attr:
                    try:
                        a = tr.get_extra_info("sockname")
                        if a is not None:
                            addrs.append(str(a))
                    except Exception:
                        pass
                if addrs:
                    self._log.info(f"[QUIC-SESSION] ({self._probe_id}) server listening on {', '.join(addrs)}")
                    return
        except Exception:
            pass

        # Definitive fallback banner to confirm we are running the new function
        self._log.info(
            f"[QUIC-SESSION] ({self._probe_id}) LISTEN READY (no .sockets on server object) at {self._listen_host}:{self._listen_port}"
        )                    
    def _ensure_connect_once(self) -> None:
        if self._connecting_task is not None or not self._peer_tuple or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _connect(): await self._connect_to(host, port)
        self._connecting_task = self._loop.create_task(_connect())  # type: ignore

    def _start_reconnect_loop(self) -> None:
        if not self._peer_tuple or self._reconnect_task is not None or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _reconnect():
            delay = 0.5
            while self._run_flag:
                # If TCP writer exists, exit (RTT runtime will flip overlay state)
                if self._quic is not None:
                    return
                await self._connect_to(host, port)
                if self._quic is not None:
                    return
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return
                delay = min(delay * 2.0, 10.0)
        self._reconnect_task = self._loop.create_task(_reconnect())  # type: ignore

    async def _connect_to(self, host: str, port: int) -> None:
        """
        Client role: establish QUIC connection to (host, port).
        Compatible with aioquic versions that do NOT accept 'server_name=' in connect().
        - Uses cfg.server_name for SNI
        - No 'server_name=' kwarg passed to quic_connect()
        """
        if not self._run_flag:
            return

        # Prepare client configuration
        cfg = self._quic_configuration_cls(is_client=True, alpn_protocols=[self._alpn])
        if self._client_insecure:
            cfg.verify_mode = ssl.CERT_NONE  # TEST ONLY
        # SNI for server name indication (works across aioquic versions)
        cfg.server_name = self._peer_name_host or host

        # Lightweight protocol wrapper that forwards events back to the session
        parent = self

        class _Proto(self._quic_protocol_cls):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._parent = parent
            def quic_event_received(self, event):
                self._parent._on_quic_event(self, event)

        self._log.info(
            f"[QUIC-SESSION] ({self._probe_id}) connecting to "
            f"{self._peer_name_host or host}:{self._peer_name_port or port} via {host}:{port} "
            f"alpn={self._alpn} insecure={self._client_insecure}"
        )
        t0 = time.perf_counter()
        try:
            # NOTE: do NOT pass 'server_name=' kwarg (older aioquic will raise TypeError)
            async with self._quic_connect(host, port, configuration=cfg, create_protocol=_Proto) as proto:
                # Adopt this live connection and keep the context open until it closes.
                self._connecting_task = None
                self._on_accept(proto)
                if self._peer_name_host:
                    self._peer_host = self._peer_name_host
                    self._peer_port = self._peer_name_port or int(port)
                    if callable(self._on_peer_set_cb):
                        try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                        except Exception: pass

                dt = (time.perf_counter() - t0) * 1000.0
                local = getattr(proto._transport, "getsockname", lambda: None)()
                remote = getattr(proto._transport, "getpeername",  lambda: None)()
                self._log.info(
                    f"[QUIC-SESSION] ({self._probe_id}) connected in {dt:.1f} ms "
                    f"local={local} peer={remote}"
                )

                # Keep the context alive while our RX task runs.
                await self._rx_task  # set in _on_accept
        except asyncio.CancelledError:
            return
        except Exception as e:
            self._log.warning(
                f"[QUIC-SESSION] ({self._probe_id}) connect failed to {host}:{port}: {e!r}"
            )
        finally:
            self._connecting_task = None
            
        """
    Client role: establish QUIC connection to (host, port).
       """
 
    # ---- accept / on-connection ----
    def _on_accept(self, proto: Any) -> None:
        """
        Adopt the live QUIC connection. Only the CLIENT proactively opens a stream;
        the SERVER waits and adopts the first incoming stream id.
        """
        if not self._peer_tuple:
            peer_id = self._alloc_server_peer_id()
            ctx = {
                "peer_id": peer_id,
                "proto": proto,
                "quic": getattr(proto, "_quic", None),
                "stream_id": None,
                "rx_buf": bytearray(),
                "rtt": StreamRTT(log=self._log.getChild(f"rtt.{peer_id}")),
                "connected": True,
                "peer_host": None,
                "peer_port": None,
            }
            self._server_peers[peer_id] = ctx
            self._server_proto_to_peer_id[id(proto)] = peer_id
            try:
                tr = getattr(proto, "_transport", None)
                laddr = tr.get_extra_info("sockname") if tr else None
                rhost, rport = self._extract_quic_peer_addr(proto)
                raddr = (rhost, rport) if rhost is not None and rport is not None else None
            except Exception:
                laddr = raddr = None
            self._log.info(f"[QUIC-SESSION] ({self._probe_id}) accept: peer_id={peer_id} local={laddr} peer={raddr}")
            try:
                if isinstance(raddr, tuple) and len(raddr) >= 2:
                    ctx["peer_host"], ctx["peer_port"] = raddr[0], int(raddr[1])
                    self._peer_host, self._peer_port = raddr[0], int(raddr[1])
                    if callable(self._on_peer_set_cb):
                        try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                        except Exception: pass
            except Exception:
                pass
            self._update_server_overlay_connected()
            return

        # Close any previous overlay peer
        try:
            if self._proto:
                self._proto.close()
        except Exception:
            pass

        self._proto = proto
        self._quic = proto._quic

        # Peer addresses (cosmetic; may be None on some stacks)
        try:
            tr = getattr(proto, "_transport", None)
            laddr = tr.get_extra_info("sockname") if tr else None
            raddr = tr.get_extra_info("peername") if tr else None
        except Exception:
            laddr = raddr = None
        self._log.info(f"[QUIC-SESSION] ({self._probe_id}) accept: local={laddr} peer={raddr}")

        # Record peer host:port if available for the dashboard
        try:
            if isinstance(raddr, tuple) and len(raddr) >= 2:
                self._peer_host, self._peer_port = raddr[0], int(raddr[1])
        except Exception:
            pass
        if callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass

        self._reset_counters()

        # === Stream selection policy =========================================
        # Client pre-opens a stream (so it can start RTT). Server waits and adopts.
        self._stream_id = None
        if self._peer_tuple:
            # We are in CLIENT role (peer_tuple != None) -> pre-open one stream
            try:
                self._stream_id = self._quic.get_next_available_stream_id()
                self._log.debug(f"[QUIC/STREAM] ({self._probe_id}) client picked stream_id={self._stream_id}")
            except Exception as e:
                self._log.debug(f"[QUIC/STREAM] ({self._probe_id}) get_next_available_stream_id() failed: {e!r}")

        # Attach RTT sender now that we can (it will only send if stream_id exists)
        self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)

        # Keep a dummy task to align lifecycle (keeps client connect() context alive)
        self._rx_task = self._loop.create_task(self._rx_dummy())  # type: ignore

        # Flush any early APP frames if we already have a stream
        self._flush_early()

    async def _rx_dummy(self):
        try:
            while self._proto and self._run_flag:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            return

    # ---- QUIC event demux ----
    def _on_quic_event(self, proto: Any, event) -> None:
        """
        Handle QUIC events. On first StreamDataReceived, adopt that stream id if we
        don't have one yet; if we already picked a different id, switch to the incoming
        id so both peers use the *same* bidirectional stream.
        """
        if not self._peer_tuple:
            peer_id = self._server_proto_to_peer_id.get(id(proto))
            if peer_id is None:
                return
            ctx = self._server_peers.get(peer_id)
            if ctx is None:
                return

            if isinstance(event, self._quic_event_negotiated):
                self._log.info(f"[QUIC/RX] ({self._probe_id}) peer_id={peer_id} ALPN negotiated: {getattr(event, 'alpn_protocol', '?')}")
                return

            if isinstance(event, self._quic_event_handshake):
                self._log.debug(f"[QUIC/RX] ({self._probe_id}) peer_id={peer_id} handshake completed")
                return

            if isinstance(event, self._quic_event_stream_data):
                sid = event.stream_id
                if ctx.get("peer_host") is None or ctx.get("peer_port") is None:
                    host, port = self._extract_quic_peer_addr(proto)
                    if host is not None and port is not None:
                        ctx["peer_host"], ctx["peer_port"] = host, port
                if ctx.get("stream_id") is None:
                    ctx["stream_id"] = sid
                    self._log.info(f"[QUIC/STREAM] ({self._probe_id}) peer_id={peer_id} adopted incoming stream_id={sid}")
                elif sid != ctx.get("stream_id"):
                    old = ctx.get("stream_id")
                    ctx["stream_id"] = sid
                    self._log.info(f"[QUIC/STREAM] ({self._probe_id}) peer_id={peer_id} switching stream_id {old} -> {sid} to match peer")
                self._on_stream_bytes(event.data, ctx=ctx, peer_id=peer_id)
                return

            if isinstance(event, self._quic_event_terminated):
                self._log.info(f"[QUIC/RX] ({self._probe_id}) peer_id={peer_id} connection terminated: {event.error_code} {event.reason_phrase!r}")
                if self._loop is not None:
                    self._loop.create_task(self._close_server_peer(peer_id))
                return
            return

        if self._proto is not proto:
            return

        if isinstance(event, self._quic_event_negotiated):
            self._log.info(f"[QUIC/RX] ({self._probe_id}) ALPN negotiated: {getattr(event, 'alpn_protocol', '?')}")
            return

        if isinstance(event, self._quic_event_handshake):
            self._log.debug(f"[QUIC/RX] ({self._probe_id}) handshake completed")
            return

        if isinstance(event, self._quic_event_stream_data):
            sid = event.stream_id

            # If we don't have a stream, adopt the incoming one.
            if self._stream_id is None:
                self._stream_id = sid
                # Ensure RTT sender is attached now that we have a stream id
                self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)
                self._log.info(f"[QUIC/STREAM] ({self._probe_id}) adopted incoming stream_id={sid}")

            # If we picked a different stream earlier (e.g., both sides opened one),
            # switch to the incoming id so that both sides converge on ONE stream.
            elif sid != self._stream_id:
                old = self._stream_id
                self._stream_id = sid
                self._log.info(f"[QUIC/STREAM] ({self._probe_id}) switching stream_id {old} -> {sid} to match peer")

            # Now process the bytes on the (adopted) stream.
            self._on_stream_bytes(event.data)
            return

        if isinstance(event, self._quic_event_terminated):
            self._log.info(f"[QUIC/RX] ({self._probe_id}) connection terminated: {event.error_code} {event.reason_phrase!r}")
            self._cleanup_after_close()
            return

    def _cleanup_after_close(self) -> None:
        self._proto = None
        self._quic = None
        self._stream_id = None
        self._set_overlay_connected(False)
        if self._peer_tuple:
            self._start_reconnect_loop()

    # ---- stream reassembly (LEN + KIND) ----
    def _on_stream_bytes(self, data: bytes, ctx: Optional[dict] = None, peer_id: Optional[int] = None) -> None:
        if not data:
            return
        self._bump_rx(data)
        if self._on_peer_rx:
            try: self._on_peer_rx(len(data))
            except Exception: pass

        rx_buf = self._rx_buf if ctx is None else ctx.setdefault("rx_buf", bytearray())
        rx_buf += data
        while True:
            if len(rx_buf) < self._LEN.size:
                return
            (n,) = self._LEN.unpack_from(rx_buf, 0)
            if n <= 0:
                del rx_buf[:self._LEN.size]
                continue
            need = self._LEN.size + n
            if len(rx_buf) < need:
                return
            body = bytes(rx_buf[self._LEN.size:need])
            del rx_buf[:need]

            kind = body[0]
            payload = body[1:]

            if kind == self._K_APP:
                if self._on_app_from_peer_bytes:
                    try: self._on_app_from_peer_bytes(len(payload))
                    except Exception: pass
                if callable(self._on_app):
                    try:
                        if peer_id is not None:
                            payload = self._server_rewrite_inbound_app(peer_id, payload)
                            self._on_app(payload, peer_id=peer_id)
                        else:
                            self._on_app(payload)
                    except TypeError:
                        try:
                            self._on_app(payload)
                        except Exception as e:
                            self._log.debug(f"[QUIC/RX] ({self._probe_id}) app callback err: {e!r}")
                    except Exception as e:
                        self._log.debug(f"[QUIC/RX] ({self._probe_id}) app callback err: {e!r}")

            elif kind == self._K_PING:
                if len(payload) >= 16:
                    tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])
                    rtt = self._rtt if ctx is None else ctx.get("rtt")
                    if rtt is not None:
                        rtt.on_ping_received(tx_ns)
                        if echo_ns:
                            rtt.on_pong_received(echo_ns)
                    if ctx is None:
                        self._send_pong_frame(tx_ns)
                    else:
                        self._send_pong_frame_for_peer(ctx, tx_ns)
                else:
                    self._log.debug(f"[QUIC/RX] ({self._probe_id}) malformed PING len={len(payload)}")

            elif kind == self._K_PONG:
                if len(payload) >= 8:
                    (echo_tx_ns,) = struct.unpack(">Q", payload[:8])
                    rtt = self._rtt if ctx is None else ctx.get("rtt")
                    if rtt is not None:
                        rtt.on_pong_received(echo_tx_ns)
                    if ctx is None:
                        was = self._overlay_connected
                        now = self._rtt.is_connected()
                        if now != was:
                            self._set_overlay_connected(now)
                else:
                    self._log.debug(f"[QUIC/RX] ({self._probe_id}) malformed PONG len={len(payload)}")

            else:
                self._log.debug(f"[QUIC/RX] ({self._probe_id}) unknown KIND=0x{kind:02x} n={n}")

    # ---- sending helpers ----
    def _send_wire_ctx(self, ctx: dict, wire: bytes) -> bool:
        quic = ctx.get("quic")
        stream_id = ctx.get("stream_id")
        proto = ctx.get("proto")
        if quic is None or stream_id is None or proto is None or not wire:
            return False
        try:
            quic.send_stream_data(int(stream_id), wire, end_stream=False)
            proto.transmit()
            self._bump_tx(wire)
            if self._on_peer_tx:
                try: self._on_peer_tx(len(wire))
                except Exception: pass
            return True
        except Exception as e:
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) server send_stream_data error peer_id={ctx.get('peer_id')}: {e!r}")
            return False

    def _send_wire(self, wire: bytes) -> None:
        if not self._quic or self._stream_id is None or not wire:
            return
        try:
            self._quic.send_stream_data(self._stream_id, wire, end_stream=False)
        except Exception as e:
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) send_stream_data error: {e!r}")
        self._schedule_transmit()

    def _schedule_transmit(self) -> None:
        """
        Ensure pending QUIC data is flushed. On some aioquic versions
        QuicConnectionProtocol.transmit() is a plain function (not a coroutine).
        Call it synchronously and do NOT 'await' it.
        """
        if not self._proto:
            return
        try:
            # Synchronous call – do NOT await
            self._proto.transmit()
        except Exception as e:
            self._log.debug(f"[QUIC/TX] ({self._probe_id}) transmit() exception: {e!r}")
            
    def _send_ping_frame(self, ping_payload: bytes) -> None:
        if not self._quic or self._stream_id is None:
            return
        body = bytes([self._K_PING]) + ping_payload
        wire = self._LEN.pack(len(body)) + body
        try:
            if len(ping_payload) >= 16:
                tx_ns, echo_ns = struct.unpack(">QQ", ping_payload[:16])
                self._log.debug(f"[QUIC/GUARD] ({self._probe_id}) PING tx: tx_ns={tx_ns} echo_ns={echo_ns}")
        except Exception:
            pass
        self._send_wire(wire)
        self._bump_tx(wire)
        if self._on_peer_tx:
            try: 
                self._on_peer_tx(len(wire))
            except Exception as e: 
                pass
        self._log.debug(f"[QUIC/TX] ({self._probe_id}) PING")

    def _send_pong_frame(self, echo_tx_ns: int) -> None:
        if not self._quic or self._stream_id is None:
            return
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        self._log.debug(f"[QUIC/GUARD] ({self._probe_id}) PONG tx: echo_tx_ns={echo_tx_ns}")
        self._send_wire(wire)
        self._bump_tx(wire)
        if self._on_peer_tx:
            try: 
                self._on_peer_tx(len(wire))
            except Exception as e: 
                pass
        self._log.debug(f"[QUIC/TX] ({self._probe_id}) PONG")

    def _send_pong_frame_for_peer(self, ctx: dict, echo_tx_ns: int) -> None:
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        wire = self._LEN.pack(len(body)) + body
        self._log.debug(f"[QUIC/GUARD] ({self._probe_id}) PONG tx peer_id={ctx.get('peer_id')}: echo_tx_ns={echo_tx_ns}")
        self._send_wire_ctx(ctx, wire)

    # ---- counters/logging ----
    def _reset_counters(self) -> None:
        self._rx_bytes = self._tx_bytes = 0
        self._rx_crc32 = self._tx_crc32 = 0
        self._log.debug(f"[QUIC/CTR] ({self._probe_id}) reset (RX=0 CRC=0x00000000, TX=0 CRC=0x00000000)")

    def _log_counters(self, direction: str) -> None:
        self._log.log(
            self._ctr_log_level,
            f"[QUIC/CTR] ({self._probe_id}) {direction} "
            f"TX={self._tx_bytes} CRC32_TX=0x{self._tx_crc32:08x} "
            f"RX={self._rx_bytes} CRC32_RX=0x{self._rx_crc32:08x}"
        )

    def _bump_tx(self, data: bytes) -> None:
        self._tx_bytes += len(data)
        self._tx_crc32 = self._z.crc32(data, self._tx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _bump_rx(self, data: bytes) -> None:
        self._rx_bytes += len(data)
        self._rx_crc32 = self._z.crc32(data, self._rx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    # ---- early buffer ----
    def _buffer_early(self, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        now = time.time()
        if self._early_deadline and now > self._early_deadline:
            self._log.info(f"[QUIC/TX] ({self._probe_id}) early-buf TTL expired; discarding {len(self._early_buf)}B")
            self._early_buf.clear()
        self._early_deadline = now + self._early_ttl
        over = (len(self._early_buf) + len(wire)) - self._early_max
        if over > 0:
            drop = min(over, len(self._early_buf))
            if drop:
                del self._early_buf[:drop]
                self._log.info(f"[QUIC/TX] ({self._probe_id}) early-buf capped: dropped={drop} keep={len(self._early_buf)} cap={self._early_max}")
        self._early_buf += wire

    def _flush_early(self) -> None:
        if not self._early_buf or not self._quic or self._stream_id is None:
            return
        try:
            n = len(self._early_buf)
            self._log.info(f"[QUIC/TX] ({self._probe_id}) flushing early-buf bytes={n}")
            self._send_wire(bytes(self._early_buf))
            self._bump_tx(self._early_buf)
        except Exception as e:
            self._log.info(f"[QUIC/TX] ({self._probe_id}) flush error: {e!r}")
        finally:
            self._early_buf.clear()
            self._early_deadline = 0.0

    # ---- overlay state (RTT-driven) ----
    def _on_rtt_state_change(self, connected: bool) -> None:
        self._set_overlay_connected(connected)

    def _set_overlay_connected(self, v: bool) -> None:
        if self._overlay_connected == v:
            return
        self._overlay_connected = v
        mode = "RTT" if self._peer_tuple else "peer-count"
        self._log.info(f"[QUIC-SESSION] ({self._probe_id}) overlay -> {'CONNECTED' if v else 'DISCONNECTED'} ({mode})")
        if v and callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass
        if callable(self._on_state):
            try: self._on_state(v)
            except Exception: pass

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        proto = ctx.get("proto")
        if proto is not None:
            self._server_proto_to_peer_id.pop(id(proto), None)
        self._server_unregister_peer_channels(peer_id)
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception as e:
                self._log.debug(f"[QUIC-SESSION] ({self._probe_id}) peer_disconnect callback err: {e!r}")
        try:
            if proto is not None:
                proto.close()
        except Exception:
            pass
        self._update_server_overlay_connected()

# -----------------------------------------------------------------------------

# --- WebSocket overlay ---------------------------------------------------------
# Requires: pip install websockets
class WebSocketPayloadCodec:
    mode = "binary"

    def encode(self, wire: bytes):
        raise NotImplementedError

    def decode(self, msg) -> Optional[bytes]:
        raise NotImplementedError


class WebSocketBinaryPayloadCodec(WebSocketPayloadCodec):
    mode = "binary"

    def encode(self, wire: bytes):
        return wire

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        return None


class WebSocketBase64PayloadCodec(WebSocketPayloadCodec):
    mode = "base64"

    def encode(self, wire: bytes):
        return base64.b64encode(wire).decode("ascii")

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        if isinstance(msg, str):
            return base64.b64decode(msg.encode("ascii"), validate=True)
        return None


class WebSocketJsonBase64PayloadCodec(WebSocketPayloadCodec):
    mode = "json-base64"

    def encode(self, wire: bytes):
        return json.dumps({"data": base64.b64encode(wire).decode("ascii")}, separators=(",", ":"))

    def decode(self, msg) -> Optional[bytes]:
        if isinstance(msg, (bytes, bytearray)):
            return bytes(msg)
        if not isinstance(msg, str):
            return None
        payload = json.loads(msg)
        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")
        data = payload.get("data")
        if not isinstance(data, str):
            raise ValueError("JSON payload must contain string field 'data'")
        return base64.b64decode(data.encode("ascii"), validate=True)


class WebSocketSession(ISession):
    """
    Overlay over one WebSocket (binary messages by default, optional base64 or JSON+base64 text frames):
      wire := KIND(1) + BYTES...
      KIND=0x00 -> APP (to upper layer)
      KIND=0x01 -> PING (payload: Q tx_ns, Q echo_ns)
      KIND=0x02 -> PONG (payload: Q echo_tx_ns)

    Features:
      - Client mode (proactive connect) and Server mode (accept multiple overlay peers)
      - Auto-reconnect (client) with backoff
      - RTT estimation via StreamRTT/StreamRTTRuntime (drives overlay 'connected')
      - Per-connection counters + running CRC32 over wire bytes (KIND+payload)
      - Early-buffer for APP frames sent before WS is up
      - Loud/structured DEBUG logging mirroring TcpStreamSession style
    """
    _K_APP  = 0x00
    _K_PING = 0x01
    _K_PONG = 0x02
    _MUX_HDR = struct.Struct(">HBHBH")
    _PAYLOAD_CODECS = {
        WebSocketBinaryPayloadCodec.mode: WebSocketBinaryPayloadCodec,
        WebSocketBase64PayloadCodec.mode: WebSocketBase64PayloadCodec,
        WebSocketJsonBase64PayloadCodec.mode: WebSocketJsonBase64PayloadCodec,
    }

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        # WS-specific knobs:
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False

        if not _has('--ws-bind'):
            p.add_argument('--ws-bind', default='::', help='WebSocket overlay bind address')
        if not _has('--ws-own-port'):
            p.add_argument('--ws-own-port', dest='ws_own_port', type=int, default=8080, help='WebSocket overlay own port')
        if not _has('--ws-peer'):
            p.add_argument('--ws-peer', default=None, help='WebSocket peer IP/FQDN')
        if not _has('--ws-peer-port'):
            p.add_argument('--ws-peer-port', type=int, default=8080, help='WebSocket peer overlay port')

        if not _has('--ws-path'):
            p.add_argument('--ws-path', default='/', help='WebSocket HTTP path (default /)')
        if not _has('--ws-subprotocol'):
            p.add_argument('--ws-subprotocol', default=None,
                           help='Optional WebSocket subprotocol (e.g. mux2)')
        if not _has('--ws-tls'):
            p.add_argument('--ws-tls', action='store_true', default=False,
                           help='Use TLS (wss://). Provide cert/key via your deployment.')
        if not _has('--ws-max-size'):
            p.add_argument('--ws-max-size', type=int, default=65535,
                           help='Maximum binary message size to accept/send (default 65535).')
        if not _has('--ws-payload-mode'):
            p.add_argument(
                '--ws-payload-mode',
                choices=sorted(WebSocketSession._PAYLOAD_CODECS.keys()),
                default='binary',
                help='WebSocket payload transfer mode: raw binary frames (default), base64 text frames, or JSON text frames with the base64 payload in the data field.'
            )
        if not _has('--ws-static-dir'):
            p.add_argument(
                '--ws-static-dir',
                default='./web',
                help="Directory to serve as a static web root on the WS port (default ./web). "
                    "Set to '' to disable."
        )
        if not _has('--ws-send-timeout'):
            p.add_argument(
                '--ws-send-timeout',
                type=float,
                default=3.0,
                help='Seconds to wait for a WebSocket frame send before forcing reconnect (default 3.0).',
            )
        if not _has('--ws-tcp-user-timeout-ms'):
            p.add_argument(
                '--ws-tcp-user-timeout-ms',
                type=int,
                default=10000,
                help='TCP_USER_TIMEOUT in milliseconds for WebSocket sockets (default 10000, 0 disables).',
            )
        if not _has('--ws-reconnect-grace'):
            p.add_argument(
                '--ws-reconnect-grace',
                type=float,
                default=3.0,
                help='Seconds to wait before reporting DISCONNECTED after WS transport loss (default 3.0).',
            )
        if not _has('--ws-proxy-mode'):
            p.add_argument(
                '--ws-proxy-mode',
                choices=('off', 'manual', 'system'),
                default='off',
                help='WebSocket client proxy mode: off (default), manual, or system (Windows only).',
            )
        if not _has('--ws-proxy-host'):
            p.add_argument('--ws-proxy-host', default='', help='Manual WebSocket proxy host (Windows only).')
        if not _has('--ws-proxy-port'):
            p.add_argument('--ws-proxy-port', type=int, default=8080, help='Manual WebSocket proxy port (default 8080).')
        if not _has('--ws-proxy-auth'):
            p.add_argument(
                '--ws-proxy-auth',
                choices=('none', 'negotiate'),
                default='none',
                help='WebSocket proxy authentication mode (Windows only): none or Negotiate.',
            )


    @staticmethod
    def from_args(args: argparse.Namespace) -> "WebSocketSession":
        return WebSocketSession(args)

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._log  = logging.getLogger("ws_session")

        # Callbacks
        self._on_app: Optional[Callable[[bytes], None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_peer_rx: Optional[Callable[[int], None]] = None
        self._on_peer_tx: Optional[Callable[[int], None]] = None
        self._on_peer_set_cb: Optional[Callable[[str, int], None]] = None
        self._on_peer_disconnect_cb: Optional[Callable[[int], None]] = None
        self._on_app_from_peer_bytes: Optional[Callable[[int], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None

        # Mode / addressing (parity with TCP)
        self._listen_host, self._listen_port = _strip_brackets(self._args.ws_bind), int(self._args.ws_own_port)
        self._peer_name_host = _strip_brackets(getattr(self._args, "ws_peer", None) or "")
        self._peer_name_port = int(getattr(self._args, "ws_peer_port", 0) or 0)
        peer_info = _resolve_cli_peer(
            self._args,
            peer_attr="ws_peer",
            peer_port_attr="ws_peer_port",
            bind_host=self._listen_host,
            socktype=socket.SOCK_STREAM,
        )
        self._peer_tuple: Optional[Tuple[str, int]] = (
            (peer_info[0], peer_info[1]) if peer_info is not None else None
        )
        self._peer_host, self._peer_port = "", 0
        self._ws_path: str = getattr(self._args, "ws_path", "/") or "/"
        self._ws_subprotocol: Optional[str] = getattr(self._args, "ws_subprotocol", None)
        self._use_tls: bool = bool(getattr(self._args, "ws_tls", False))
        self._ws_max_size: int = int(getattr(self._args, "ws_max_size", 65535))
        self._ws_payload_mode: str = str(getattr(self._args, "ws_payload_mode", "binary") or "binary").lower()
        codec_cls = self._PAYLOAD_CODECS.get(self._ws_payload_mode)
        if codec_cls is None:
            raise ValueError(f"Unsupported --ws-payload-mode: {self._ws_payload_mode}")
        self._ws_payload_codec: WebSocketPayloadCodec = codec_cls()
        self._ws_send_timeout_s: float = max(0.0, float(getattr(self._args, "ws_send_timeout", 3.0) or 0.0))
        self._ws_tcp_user_timeout_ms: int = max(0, int(getattr(self._args, "ws_tcp_user_timeout_ms", 10000) or 0))
        self._ws_reconnect_grace_s: float = max(0.0, float(getattr(self._args, "ws_reconnect_grace", 3.0) or 0.0))
        self._ws_proxy_mode: str = str(getattr(self._args, "ws_proxy_mode", "off") or "off").lower()
        self._ws_proxy_host: str = _strip_brackets(str(getattr(self._args, "ws_proxy_host", "") or ""))
        self._ws_proxy_port: int = max(0, int(getattr(self._args, "ws_proxy_port", 8080) or 0))
        self._ws_proxy_auth: str = str(getattr(self._args, "ws_proxy_auth", "none") or "none").lower()
        # Reverse proxies can negotiate permessage-deflate but then stall or drop
        # tiny control messages. Keep overlay framing simple and deterministic.
        self._ws_compression = None

        # Runtime
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._run_flag: bool = False

        # WS connection & tasks
        self._ws = None                           # type: ignore
        self._server = None                       # websockets.server.Serve or similar
        self._rx_task: Optional[asyncio.Task] = None
        self._tx_task: Optional[asyncio.Task] = None
        self._connecting_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._disconnect_task: Optional[asyncio.Task] = None
        self._tx_queue: "asyncio.Queue[tuple[bytes, Optional[Callable[[], None]]]]" = asyncio.Queue()
        self._server_connected_evt = asyncio.Event()
        self._server_peers: Dict[int, dict] = {}
        self._server_peer_by_ws_id: Dict[int, int] = {}
        self._server_next_peer_id: int = 1
        self._server_chan_to_peer: Dict[int, Tuple[int, int]] = {}
        self._server_peer_chan_to_mux: Dict[Tuple[int, int], int] = {}
        self._server_next_mux_chan: int = 1

        # Early buffer (APP/CTRL frames preserved as individual WS messages)
        self._early_buf: Deque[tuple[bytes, Optional[Callable[[], None]]]] = deque()
        self._early_buf_bytes = 0
        self._early_max = 1 * 1024 * 1024
        self._early_ttl = 3.0
        self._early_deadline = 0.0

        # Counters
        import zlib as _z
        self._z = _z
        self._rx_bytes = 0
        self._tx_bytes = 0
        self._rx_crc32 = 0
        self._tx_crc32 = 0
        self._ctr_log_level = logging.DEBUG
        self._probe_id = f"{id(self)&0xFFFF:04x}"

        # RTT
        self._rtt = StreamRTT(log=self._log.getChild("rtt"))
        self._rtt_rt = StreamRTTRuntime(self._rtt)
        self._overlay_connected = False
        self.connection_epoch: int = 0

        # Static HTTP root
        self._ws_static_dir: Optional[str] = getattr(self._args, "ws_static_dir", "./web") or None
        self._static_http_probe_delays_s: tuple[float, ...] = (0.0, 0.05, 0.25, 1.0)

    # ---- ISession wiring ------------------------------------------------------
    def set_on_app_payload(self, cb): self._on_app = cb
    def set_on_state_change(self, cb): self._on_state = cb
    def set_on_peer_rx(self, cb): self._on_peer_rx = cb
    def set_on_peer_tx(self, cb): self._on_peer_tx = cb
    def set_on_peer_set(self, cb): self._on_peer_set_cb = cb
    def set_on_peer_disconnect(self, cb): self._on_peer_disconnect_cb = cb
    def set_on_app_from_peer_bytes(self, cb): self._on_app_from_peer_bytes = cb
    def set_on_transport_epoch_change(self, cb): self._on_transport_epoch_change = cb

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._run_flag = True

        # Attach RTT driver (send function gets attached when WS is up)
        if self._peer_tuple:
            self._rtt_rt.attach(send_ping_fn=None, on_state_change=self._on_rtt_state_change)

        if self._peer_tuple:
            # CLIENT
            self._peer_host = self._peer_name_host or self._peer_tuple[0]
            self._peer_port = self._peer_name_port or self._peer_tuple[1]
            self._log.info(
                f"[WS-SESSION] ({self._probe_id}) start; CLIENT -> "
                f"{self._peer_host}:{self._peer_port}{self._ws_path} "
                f"resolved={self._peer_tuple} tls={self._use_tls}"
            )
            self._ensure_connect_once()
        else:
            # SERVER
            self._log.info(f"[WS-SESSION] ({self._probe_id}) start; SERVER bind={self._listen_host}:{self._listen_port}{self._ws_path} tls={self._use_tls}")
            await self._start_server()

    async def stop(self) -> None:
        self._log.info(f"[WS-SESSION] ({self._probe_id}) stopping")
        self._run_flag = False

        if self._peer_tuple:
            self._rtt_rt.detach()

        for t in (self._connecting_task, self._reconnect_task):
            if t: t.cancel()
        self._connecting_task = None
        self._reconnect_task = None
        if self._disconnect_task:
            self._disconnect_task.cancel()
            self._disconnect_task = None

        for attr in ("_rx_task", "_tx_task"):
            try:
                task = getattr(self, attr)
                if task:
                    task.cancel()
            except Exception:
                pass
            setattr(self, attr, None)

        try:
            if self._ws:
                await self._ws.close()           # type: ignore
        except Exception:
            pass
        self._ws = None

        for peer_id in list(self._server_peers.keys()):
            await self._close_server_peer(peer_id)
        self._server_connected_evt.clear()

        try:
            if self._server:
                self._server.close()             # type: ignore
                await self._server.wait_closed() # type: ignore
        except Exception:
            pass
        self._server = None

        self._set_overlay_connected(False)

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if not self._peer_tuple:
            if self._server_peers:
                return True
            try:
                await asyncio.wait_for(self._server_connected_evt.wait(), timeout)
                return True
            except asyncio.TimeoutError:
                return False
        return await self._rtt_rt.wait_connected(timeout)

    def is_connected(self) -> bool:
        if not self._peer_tuple:
            return bool(self._server_peers)
        return self._rtt.is_connected()

    def get_metrics(self) -> SessionMetrics:
        try:
            r = self._rtt
            return SessionMetrics(
                rtt_sample_ms=getattr(r, "rtt_sample_ms", None),
                rtt_est_ms=getattr(r, "rtt_est_ms", None),
                last_rtt_ok_ns=getattr(r, "last_rtt_ok_ns", None),
            )
        except Exception:
            return SessionMetrics()

    # ---- Data path (APP) ------------------------------------------------------
    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        wire = bytes([self._K_APP]) + payload

        if not self._peer_tuple:
            if not self._server_peers and self._ws is not None:
                self._schedule_send(wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
                return len(payload)
            routed = self._server_rewrite_outbound_app(payload)
            if routed is None:
                self._log.debug(f"[WS/TX] ({self._probe_id}) drop unroutable server APP len={len(payload)}")
                return 0
            peer_id, payload = routed
            ctx = self._server_peers.get(peer_id)
            if not ctx:
                self._log.debug(f"[WS/TX] ({self._probe_id}) drop APP for missing peer_id={peer_id}")
                return 0
            self._schedule_server_send(ctx, bytes([self._K_APP]) + payload, on_sent=lambda: self._notify_peer_tx(len(payload) + 1))
            return len(payload)

        if self._ws is None:
            self._buffer_early(wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
            self._log.debug(f"[WS/TX] ({self._probe_id}) early-buffer APP bytes={len(wire)} buf={len(self._early_buf)}")
            if self._peer_tuple:
                self._ensure_connect_once()
            return len(payload)

        self._schedule_send(wire, on_sent=lambda: self._notify_peer_tx(len(wire)))
        return len(payload)

    def _alloc_server_peer_id(self) -> int:
        peer_id = self._server_next_peer_id
        while peer_id in self._server_peers:
            peer_id += 1
            if peer_id > 0xFFFF:
                peer_id = 1
        self._server_next_peer_id = 1 if peer_id >= 0xFFFF else (peer_id + 1)
        return peer_id

    def _alloc_server_mux_chan(self) -> int:
        chan = self._server_next_mux_chan
        while chan in self._server_chan_to_peer:
            chan += 2
            if chan > 0xFFFF:
                chan = 1
        self._server_next_mux_chan = 1 if chan >= 0xFFFF else (chan + 2)
        return chan

    def _rewrite_mux_chan_id(self, payload: bytes, new_chan: int) -> bytes:
        if len(payload) < self._MUX_HDR.size:
            return payload
        _, proto, counter, mtype, dlen = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        if len(payload) < self._MUX_HDR.size + dlen:
            return payload
        return self._MUX_HDR.pack(new_chan, proto, counter, mtype, dlen) + payload[self._MUX_HDR.size:self._MUX_HDR.size + dlen]

    def _server_rewrite_inbound_app(self, peer_id: int, payload: bytes) -> bytes:
        if len(payload) < self._MUX_HDR.size:
            return payload
        try:
            peer_chan, _proto, _counter, _mtype, dlen = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        except Exception:
            return payload
        if len(payload) < self._MUX_HDR.size + dlen:
            return payload
        key = (peer_id, peer_chan)
        mux_chan = self._server_peer_chan_to_mux.get(key)
        if mux_chan is None:
            mux_chan = self._alloc_server_mux_chan()
            self._server_peer_chan_to_mux[key] = mux_chan
            self._server_chan_to_peer[mux_chan] = key
        return self._rewrite_mux_chan_id(payload, mux_chan)

    def _server_rewrite_outbound_app(self, payload: bytes) -> Optional[Tuple[int, bytes]]:
        if len(payload) < self._MUX_HDR.size:
            return None
        try:
            mux_chan, _proto, _counter, _mtype, dlen = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        except Exception:
            return None
        if len(payload) < self._MUX_HDR.size + dlen:
            return None
        mapped = self._server_chan_to_peer.get(mux_chan)
        if mapped is None:
            # Server-initiated channels (for peer-installed services) may not have an
            # inbound mapping yet. If exactly one peer is connected, route directly.
            if len(self._server_peers) == 1:
                only_peer_id = next(iter(self._server_peers.keys()))
                mapped = (int(only_peer_id), int(mux_chan))
                self._server_peer_chan_to_mux[mapped] = int(mux_chan)
                self._server_chan_to_peer[int(mux_chan)] = mapped
            else:
                return None
        peer_id, peer_chan = mapped
        return peer_id, self._rewrite_mux_chan_id(payload, peer_chan)

    def _server_unregister_peer_channels(self, peer_id: int) -> None:
        for key, mux_chan in list(self._server_peer_chan_to_mux.items()):
            if key[0] != peer_id:
                continue
            self._server_peer_chan_to_mux.pop(key, None)
            self._server_chan_to_peer.pop(mux_chan, None)

    def _update_server_overlay_connected(self) -> None:
        connected = bool(self._server_peers)
        if connected:
            self._server_connected_evt.set()
        else:
            self._server_connected_evt.clear()
        self._set_overlay_connected(connected)

    @staticmethod
    def _format_peer_label(host: Optional[object], port: Optional[object]) -> Optional[str]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return f"[{host_s}]:{port_i}" if ":" in host_s and not host_s.startswith("[") else f"{host_s}:{port_i}"
        except Exception:
            return None

    def get_overlay_peers_snapshot(self) -> list[dict]:
        """
        Return per-overlay-peer rows for admin diagnostics.

        For WS server mode this returns one row per connected websocket peer and
        includes the mux channels owned by that peer, allowing higher layers to
        split UDP/TCP counters by peer.
        """
        rows: list[dict] = []
        if self._peer_tuple:
            peer_label = self._format_peer_label(self._peer_host, self._peer_port)
            rows.append(
                {
                    "peer_id": 0,
                    "connected": bool(self.is_connected()),
                    "state": "connected" if self.is_connected() else "connecting",
                    "peer": peer_label,
                    "mux_chans": [],
                    "rtt_est_ms": getattr(self._rtt, "rtt_est_ms", None),
                }
            )
            return rows

        rows.append(
            {
                "peer_id": -1,
                "connected": False,
                "state": "listening",
                "peer": None,
                "mux_chans": [],
                "rtt_est_ms": None,
                "listening": True,
            }
        )

        mux_by_peer: Dict[int, list[int]] = {}
        for mux_chan, mapped in self._server_chan_to_peer.items():
            try:
                peer_id, _peer_chan = mapped
                mux_by_peer.setdefault(int(peer_id), []).append(int(mux_chan))
            except Exception:
                continue

        peer_ids: set[int] = set(int(p) for p in self._server_peers.keys())
        peer_ids.update(int(p) for p in mux_by_peer.keys())

        for peer_id in sorted(peer_ids):
            ctx = self._server_peers.get(peer_id, {})
            ws = ctx.get("ws") if isinstance(ctx, dict) else None
            remote = getattr(ws, "remote_address", None) if ws is not None else None
            host = remote[0] if isinstance(remote, tuple) and len(remote) >= 2 else None
            port = remote[1] if isinstance(remote, tuple) and len(remote) >= 2 else None
            peer_label = self._format_peer_label(host, port)
            rtt = ctx.get("rtt") if isinstance(ctx, dict) else None
            rows.append(
                {
                    "peer_id": peer_id,
                    "connected": bool(peer_id in self._server_peers),
                    "state": "connected" if peer_id in self._server_peers else "connecting",
                    "peer": peer_label,
                    "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                    "rtt_est_ms": getattr(rtt, "rtt_est_ms", None),
                }
            )

        return rows

    # ---- Internals ------------------------------------------------------------

    @staticmethod
    def _format_connect_authority(host: str, port: int) -> str:
        host_s = _strip_brackets(str(host or ""))
        if ":" in host_s and not host_s.startswith("["):
            host_s = f"[{host_s}]"
        return f"{host_s}:{int(port)}"

    @staticmethod
    def _parse_proxy_authority(value: str, default_port: int = 8080) -> Optional[Tuple[str, int]]:
        text = str(value or "").strip()
        if not text:
            return None
        if "://" in text:
            text = text.split("://", 1)[1]
        text = text.split("/", 1)[0].strip()
        if not text:
            return None
        host = text
        port = int(default_port)
        if text.startswith("["):
            end = text.find("]")
            if end == -1:
                return None
            host = text[1:end]
            rest = text[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
        elif text.count(":") == 1:
            base, maybe_port = text.rsplit(":", 1)
            if maybe_port.isdigit():
                host = base
                port = int(maybe_port)
        return (_strip_brackets(host), int(port)) if host else None

    @classmethod
    def _parse_proxy_spec(cls, spec: str, secure: bool = False) -> Optional[Tuple[str, int]]:
        preferred = ("https", "wss") if secure else ("http", "ws")
        fallback = None
        for raw_item in str(spec or "").split(";"):
            item = raw_item.strip()
            if not item:
                continue
            if "=" not in item:
                parsed = cls._parse_proxy_authority(item)
                if parsed:
                    fallback = parsed
                continue
            scheme, value = item.split("=", 1)
            scheme = scheme.strip().lower()
            parsed = cls._parse_proxy_authority(value)
            if not parsed:
                continue
            if scheme in preferred:
                return parsed
            if fallback is None:
                fallback = parsed
        return fallback

    def _build_windows_negotiate_spn(self, host: str) -> str:
        host_s = _strip_brackets(str(host or "")).strip()
        if not host_s:
            raise RuntimeError("empty proxy host for Negotiate target name")
        upper = host_s.upper()
        if "." in upper:
            parts = upper.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else upper
            return f"HTTP/{host_s}@{domain}"
        return f"HTTP/{host_s}"

    def _build_proxy_connect_request(self, target_host: str, target_port: int, auth_header: Optional[str] = None) -> bytes:
        authority = self._format_connect_authority(target_host, target_port)
        lines = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
            "Connection: keep-alive",
            "Proxy-Connection: keep-alive",
            "User-Agent: ObstacleBridge-ws-proxy/1.0",
        ]
        if auth_header:
            lines.append(f"Proxy-Authorization: {auth_header}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    def _proxy_feature_enabled(self) -> bool:
        return bool(self._peer_tuple) and self._ws_proxy_mode != "off"

    def _get_ws_proxy_endpoint(self, target_host: str, target_port: int) -> Optional[Tuple[str, int]]:
        self._log.debug(
            "[WS-PROXY] (%s) endpoint lookup target=%s mode=%s peer_configured=%s platform=%s tls=%s",
            self._probe_id,
            self._format_connect_authority(target_host, target_port),
            self._ws_proxy_mode,
            bool(self._peer_tuple),
            sys.platform,
            self._use_tls,
        )
        if not self._proxy_feature_enabled():
            self._log.debug("[WS-PROXY] (%s) proxy feature disabled", self._probe_id)
            return None
        if sys.platform != "win32":
            self._log.debug("[WS-PROXY] (%s) rejecting proxy lookup on unsupported platform=%s", self._probe_id, sys.platform)
            raise RuntimeError("WebSocket proxy support is currently available on Windows only")
        if self._ws_proxy_mode == "manual":
            if not self._ws_proxy_host or self._ws_proxy_port <= 0:
                self._log.debug(
                    "[WS-PROXY] (%s) manual mode missing host/port host=%r port=%s",
                    self._probe_id,
                    self._ws_proxy_host,
                    self._ws_proxy_port,
                )
                raise RuntimeError("manual WebSocket proxy mode requires --ws-proxy-host and --ws-proxy-port")
            self._log.debug(
                "[WS-PROXY] (%s) manual proxy selected endpoint=%s:%d",
                self._probe_id,
                self._ws_proxy_host,
                int(self._ws_proxy_port),
            )
            return self._ws_proxy_host, int(self._ws_proxy_port)
        if self._ws_proxy_mode == "system":
            lookup_url = f"http://{self._format_connect_authority(target_host, target_port)}"
            self._log.debug("[WS-PROXY] (%s) system proxy lookup url=%s secure=%s", self._probe_id, lookup_url, self._use_tls)
            endpoint = self._win_get_proxy_for_url(
                lookup_url,
                secure=self._use_tls,
            )
            if endpoint is None:
                self._log.debug("[WS-PROXY] (%s) system proxy lookup returned no endpoint", self._probe_id)
                raise RuntimeError("system proxy mode did not return a proxy for the websocket target")
            self._log.debug("[WS-PROXY] (%s) system proxy selected endpoint=%s:%d", self._probe_id, endpoint[0], int(endpoint[1]))
            return endpoint
        self._log.debug("[WS-PROXY] (%s) unsupported mode=%s", self._probe_id, self._ws_proxy_mode)
        raise RuntimeError(f"unsupported --ws-proxy-mode: {self._ws_proxy_mode}")

    def _win_get_proxy_for_url(self, url: str, secure: bool = False) -> Optional[Tuple[str, int]]:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
        HINTERNET = ctypes.c_void_p

        winhttp.WinHttpGetIEProxyConfigForCurrentUser.restype = wintypes.BOOL
        winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [ctypes.c_void_p]
        winhttp.WinHttpOpen.restype = HINTERNET
        winhttp.WinHttpOpen.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        winhttp.WinHttpGetProxyForUrl.restype = wintypes.BOOL
        winhttp.WinHttpGetProxyForUrl.argtypes = [
            HINTERNET,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        winhttp.WinHttpCloseHandle.restype = wintypes.BOOL
        winhttp.WinHttpCloseHandle.argtypes = [HINTERNET]

        class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
            _fields_ = [
                ("fAutoDetect", wintypes.BOOL),
                ("lpszAutoConfigUrl", ctypes.c_void_p),
                ("lpszProxy", ctypes.c_void_p),
                ("lpszProxyBypass", ctypes.c_void_p),
            ]

        class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
            _fields_ = [
                ("dwFlags", wintypes.DWORD),
                ("dwAutoDetectFlags", wintypes.DWORD),
                ("lpszAutoConfigUrl", wintypes.LPCWSTR),
                ("lpvReserved", wintypes.LPVOID),
                ("dwReserved", wintypes.DWORD),
                ("fAutoLogonIfChallenged", wintypes.BOOL),
            ]

        class WINHTTP_PROXY_INFO(ctypes.Structure):
            _fields_ = [
                ("dwAccessType", wintypes.DWORD),
                ("lpszProxy", ctypes.c_void_p),
                ("lpszProxyBypass", ctypes.c_void_p),
            ]

        WINHTTP_ACCESS_TYPE_NO_PROXY = 1
        WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
        WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
        WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002
        WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
        WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

        def _wide(ptr: int) -> str:
            return ctypes.wstring_at(ptr) if ptr else ""

        def _free(ptr: int) -> None:
            if ptr:
                kernel32.GlobalFree(ctypes.c_void_p(ptr))

        manual_proxy = ""
        auto_url = ""
        auto_detect = True
        ie_cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
        try:
            if bool(winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(ie_cfg))):
                auto_detect = bool(ie_cfg.fAutoDetect)
                manual_proxy = _wide(ie_cfg.lpszProxy)
                auto_url = _wide(ie_cfg.lpszAutoConfigUrl)
                self._log.debug(
                    "[WS-PROXY] (%s) IE proxy config auto_detect=%s auto_config_url=%r manual_proxy=%r",
                    self._probe_id,
                    auto_detect,
                    auto_url,
                    manual_proxy,
                )
            else:
                self._log.debug(
                    "[WS-PROXY] (%s) WinHttpGetIEProxyConfigForCurrentUser failed last_error=%s",
                    self._probe_id,
                    ctypes.get_last_error(),
                )
            parsed = self._parse_proxy_spec(manual_proxy, secure=secure)
            if parsed:
                self._log.debug(
                    "[WS-PROXY] (%s) using manual IE proxy endpoint=%s:%d",
                    self._probe_id,
                    parsed[0],
                    int(parsed[1]),
                )
                return parsed
        finally:
            _free(getattr(ie_cfg, "lpszAutoConfigUrl", 0))
            _free(getattr(ie_cfg, "lpszProxy", 0))
            _free(getattr(ie_cfg, "lpszProxyBypass", 0))

        session = winhttp.WinHttpOpen(
            "ObstacleBridge/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            None,
            None,
            0,
        )
        if not session:
            raise RuntimeError(f"WinHttpOpen failed: {ctypes.get_last_error()}")
        try:
            opts = WINHTTP_AUTOPROXY_OPTIONS()
            if auto_url:
                opts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
                opts.lpszAutoConfigUrl = auto_url
                self._log.debug("[WS-PROXY] (%s) WinHTTP auto-proxy using PAC url=%r for %s", self._probe_id, auto_url, url)
            else:
                opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
                opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
                self._log.debug(
                    "[WS-PROXY] (%s) WinHTTP auto-proxy using auto_detect=%s flags=DHCP|DNS_A for %s",
                    self._probe_id,
                    auto_detect,
                    url,
                )
            opts.fAutoLogonIfChallenged = True
            info = WINHTTP_PROXY_INFO()
            if not bool(winhttp.WinHttpGetProxyForUrl(session, str(url), ctypes.byref(opts), ctypes.byref(info))):
                self._log.debug(
                    "[WS-PROXY] (%s) WinHttpGetProxyForUrl returned no proxy last_error=%s url=%s",
                    self._probe_id,
                    ctypes.get_last_error(),
                    url,
                )
                return None
            try:
                raw_proxy = _wide(info.lpszProxy)
                self._log.debug(
                    "[WS-PROXY] (%s) WinHttpGetProxyForUrl access_type=%s raw_proxy=%r",
                    self._probe_id,
                    int(info.dwAccessType),
                    raw_proxy,
                )
                if int(info.dwAccessType) != WINHTTP_ACCESS_TYPE_NAMED_PROXY:
                    self._log.debug("[WS-PROXY] (%s) WinHTTP access type is not named proxy", self._probe_id)
                    return None
                parsed = self._parse_proxy_spec(raw_proxy, secure=secure)
                self._log.debug("[WS-PROXY] (%s) parsed WinHTTP proxy endpoint=%r", self._probe_id, parsed)
                return parsed
            finally:
                _free(getattr(info, "lpszProxy", 0))
                _free(getattr(info, "lpszProxyBypass", 0))
        finally:
            winhttp.WinHttpCloseHandle(session)

    def _win_build_negotiate_token(self, target_name: str, challenge: Optional[bytes] = None) -> str:
        secur32 = ctypes.WinDLL("secur32", use_last_error=True)

        class CredHandle(ctypes.Structure):
            _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]

        class CtxtHandle(ctypes.Structure):
            _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]

        class TimeStamp(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.DWORD)]

        class SecBuffer(ctypes.Structure):
            _fields_ = [
                ("cbBuffer", wintypes.ULONG),
                ("BufferType", wintypes.ULONG),
                ("pvBuffer", ctypes.c_void_p),
            ]

        class SecBufferDesc(ctypes.Structure):
            _fields_ = [
                ("ulVersion", wintypes.ULONG),
                ("cBuffers", wintypes.ULONG),
                ("pBuffers", ctypes.POINTER(SecBuffer)),
            ]

        SECPKG_CRED_OUTBOUND = 2
        SECURITY_NATIVE_DREP = 0x00000010
        ISC_REQ_CONFIDENTIALITY = 0x00000010
        SECBUFFER_VERSION = 0
        SECBUFFER_TOKEN = 2
        SEC_E_OK = 0x00000000
        SEC_I_CONTINUE_NEEDED = 0x00090312

        expiry = TimeStamp()
        cred = CredHandle()
        status = secur32.AcquireCredentialsHandleW(
            None,
            "Negotiate",
            SECPKG_CRED_OUTBOUND,
            None,
            None,
            None,
            None,
            ctypes.byref(cred),
            ctypes.byref(expiry),
        )
        if int(status) != SEC_E_OK:
            raise RuntimeError(f"AcquireCredentialsHandleW failed: 0x{int(status) & 0xFFFFFFFF:08x}")

        ctx = CtxtHandle()
        attrs = wintypes.ULONG()
        out_buf_raw = ctypes.create_string_buffer(65536)
        out_buf = SecBuffer(len(out_buf_raw), SECBUFFER_TOKEN, ctypes.cast(out_buf_raw, ctypes.c_void_p))
        out_desc = SecBufferDesc(SECBUFFER_VERSION, 1, ctypes.pointer(out_buf))

        # Keep this aligned with the existing Windows sample's narrow behavior:
        # generate an outbound Negotiate token from the current logon context.
        # A full multi-round SSPI challenge exchange can be added later if needed.
        _ignored_challenge = challenge
        in_desc_ptr = None

        try:
            status = secur32.InitializeSecurityContextW(
                ctypes.byref(cred),
                None,
                ctypes.c_wchar_p(target_name),
                ISC_REQ_CONFIDENTIALITY,
                0,
                SECURITY_NATIVE_DREP,
                in_desc_ptr,
                0,
                ctypes.byref(ctx),
                ctypes.byref(out_desc),
                ctypes.byref(attrs),
                ctypes.byref(expiry),
            )
            if int(status) not in (SEC_E_OK, SEC_I_CONTINUE_NEEDED):
                raise RuntimeError(f"InitializeSecurityContextW failed: 0x{int(status) & 0xFFFFFFFF:08x}")
            if int(out_buf.cbBuffer) <= 0:
                raise RuntimeError("InitializeSecurityContextW returned no token")
            return base64.b64encode(out_buf_raw.raw[: int(out_buf.cbBuffer)]).decode("ascii")
        finally:
            with contextlib.suppress(Exception):
                if ctx.dwLower or ctx.dwUpper:
                    secur32.DeleteSecurityContext(ctypes.byref(ctx))
            with contextlib.suppress(Exception):
                secur32.FreeCredentialsHandle(ctypes.byref(cred))

    def _read_http_proxy_response(self, sock: socket.socket) -> Tuple[int, Dict[str, List[str]]]:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                raise RuntimeError("proxy response headers too large")
        header_blob, _, _rest = data.partition(b"\r\n\r\n")
        lines = header_blob.decode("iso-8859-1", "replace").split("\r\n")
        if not lines or len(lines[0].split(" ")) < 2:
            raise RuntimeError("invalid proxy response")
        parts = lines[0].split(" ", 2)
        status_code = int(parts[1]) if parts[1].isdigit() else 0
        headers: Dict[str, List[str]] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), []).append(value.strip())
        return status_code, headers

    def _open_ws_proxy_socket_blocking(self, target_host: str, target_port: int) -> socket.socket:
        proxy = self._get_ws_proxy_endpoint(target_host, target_port)
        if proxy is None:
            raise RuntimeError("no proxy endpoint available")
        proxy_host, proxy_port = proxy
        auth_mode = self._ws_proxy_auth
        challenge_blob = None
        attempts = 0
        self._log.debug(
            "[WS-PROXY] (%s) opening proxy tunnel target=%s via=%s:%d auth=%s",
            self._probe_id,
            self._format_connect_authority(target_host, target_port),
            proxy_host,
            int(proxy_port),
            auth_mode,
        )
        while attempts < 3:
            attempts += 1
            self._log.debug("[WS-PROXY] (%s) CONNECT attempt=%d proxy=%s:%d", self._probe_id, attempts, proxy_host, int(proxy_port))
            sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=30.0)
            try:
                auth_header = None
                if auth_mode == "negotiate" and attempts > 1:
                    self._log.debug(
                        "[WS-PROXY] (%s) building Negotiate token challenge_present=%s",
                        self._probe_id,
                        challenge_blob is not None,
                    )
                    auth_header = "Negotiate " + self._win_build_negotiate_token(
                        self._build_windows_negotiate_spn(proxy_host),
                        challenge=challenge_blob,
                    )
                request = self._build_proxy_connect_request(target_host, target_port, auth_header=auth_header)
                sock.sendall(request)
                status_code, headers = self._read_http_proxy_response(sock)
                self._log.debug(
                    "[WS-PROXY] (%s) CONNECT response status=%s proxy_authenticate=%s",
                    self._probe_id,
                    status_code,
                    headers.get("proxy-authenticate", []),
                )
                if status_code == 200:
                    self._log.debug("[WS-PROXY] (%s) CONNECT tunnel established on attempt=%d", self._probe_id, attempts)
                    sock.setblocking(False)
                    return sock
                if status_code != 407:
                    raise RuntimeError(f"proxy CONNECT failed with HTTP {status_code}")
                if auth_mode != "negotiate":
                    raise RuntimeError("proxy requires authentication but --ws-proxy-auth is not negotiate")
                negotiate_headers = []
                for value in headers.get("proxy-authenticate", []):
                    if value.lower().startswith("negotiate"):
                        negotiate_headers.append(value)
                if not negotiate_headers:
                    raise RuntimeError("proxy does not offer Negotiate authentication")
                challenge_blob = None
                token = negotiate_headers[0][len("Negotiate"):].strip()
                if token:
                    self._log.debug("[WS-PROXY] (%s) proxy supplied Negotiate challenge token", self._probe_id)
                    challenge_blob = base64.b64decode(token)
                else:
                    self._log.debug("[WS-PROXY] (%s) proxy requested Negotiate without challenge token", self._probe_id)
            except Exception:
                sock.close()
                raise
            sock.close()
        raise RuntimeError("proxy authentication failed after multiple attempts")

    async def _open_ws_proxy_socket(self, target_host: str, target_port: int) -> socket.socket:
        return await asyncio.to_thread(self._open_ws_proxy_socket_blocking, target_host, int(target_port))

    def _describe_transport_state(self, connection) -> str:
        transport = getattr(connection, "transport", None)
        if transport is None:
            return "transport=missing"

        parts: list[str] = []
        try:
            parts.append(f"wbuf={transport.get_write_buffer_size()}")
        except Exception as e:
            parts.append(f"wbuf=?({e!r})")
        try:
            parts.append(f"closing={bool(transport.is_closing())}")
        except Exception as e:
            parts.append(f"closing=?({e!r})")

        try:
            sockname = transport.get_extra_info("sockname")
            if sockname is not None:
                parts.append(f"sockname={sockname}")
        except Exception:
            pass
        try:
            peername = transport.get_extra_info("peername")
            if peername is not None:
                parts.append(f"peer={peername}")
        except Exception:
            pass
        return " ".join(parts)

    def _log_static_http_decision(
        self,
        *,
        method: str,
        req_path: str,
        status: int,
        target,
        ctype: str,
        content_length: int,
        body_length: int,
        note: str = "",
    ) -> None:
        target_txt = "-" if target is None else str(target)
        suffix = f" note={note}" if note else ""
        self._log.debug(
            f"[WS/HTTP] ({self._probe_id}) method={method} path={req_path} status={status} "
            f"target={target_txt} ctype={ctype} content_length={content_length} body_length={body_length}{suffix}"
        )

    def _schedule_static_http_debug_probes(
        self,
        connection,
        *,
        method: str,
        req_path: str,
        status: int,
        target,
        body_length: int,
    ) -> None:
        loop = self._loop
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
        if loop is None:
            return

        target_txt = "-" if target is None else str(target)

        def _emit_probe(delay_s: float) -> None:
            self._log.debug(
                f"[WS/HTTP] ({self._probe_id}) probe dt={delay_s:.3f}s method={method} "
                f"path={req_path} status={status} body_length={body_length} target={target_txt} "
                f"{self._describe_transport_state(connection)}"
            )

        for delay_s in self._static_http_probe_delays_s:
            try:
                if delay_s <= 0:
                    loop.call_soon(_emit_probe, delay_s)
                else:
                    loop.call_later(delay_s, _emit_probe, delay_s)
            except Exception as e:
                self._log.debug(
                    f"[WS/HTTP] ({self._probe_id}) failed to schedule probe delay={delay_s:.3f}s "
                    f"path={req_path}: {e!r}"
                )

    async def _start_server(self) -> None:
        """
        Start the WebSocket server (websockets >= 12.x) AND a tiny static file server
        on the same port. We use process_request to serve HTTP before any WS upgrade.

        - GET/HEAD to any path under --ws-static-dir => static file (200) or 404.
        - A proper WS Upgrade to self._ws_path continues to the WS handler.
        - If --ws-static-dir is empty or missing on disk, only WS is served.
        """
        try:
            import websockets
            from websockets.http11 import Response
            from websockets.datastructures import Headers
        except Exception as e:
            raise RuntimeError("websockets package is required for WebSocketSession") from e

        # Optional TLS
        ssl_ctx = None
        if self._use_tls:
            import ssl
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        subprotocols = [self._ws_subprotocol] if self._ws_subprotocol else None

        # --------- simple static file server (process_request hook) ----------
        # Return (status_code, headers, body_bytes) to short-circuit the WS upgrade.
        # Return None to let websockets proceed with the WS handshake.

        try:
            from websockets.http11 import Response  # modern API (>= 14)
        except Exception:
            Response = None  # legacy path (12/13) will return (status, headers, body)

        from pathlib import Path
        from urllib.parse import unquote
        import mimetypes
        mimetypes.add_type("text/javascript", ".js")   # or "application/javascript"
        mimetypes.add_type("image/svg+xml", ".svg")
        import datetime

        # Resolve static root if present
        static_root = None
        if self._ws_static_dir:
            try:
                p = Path(self._ws_static_dir).resolve(strict=False)
                if p.exists() and p.is_dir():
                    static_root = p
                    self._log.info(f"[WS-SESSION] ({self._probe_id}) static HTTP root: {static_root}")
                else:
                    self._log.info(f"[WS-SESSION] ({self._probe_id}) --ws-static-dir set but not present; static HTTP disabled")
            except Exception as e:
                self._log.info(f"[WS-SESSION] ({self._probe_id}) failed to resolve --ws-static-dir: {e!r}")

        def _http_headers(status: int, length: int, ctype: str = "application/octet-stream"):
            now = datetime.datetime.utcnow()
            return [
                ("Date", now.strftime("%a, %d %b %Y %H:%M:%S GMT")),
                ("Server", "ws-mini/1.0"),
                ("Content-Type", ctype),
                ("Content-Length", str(max(0, length))),
                ("Cache-Control", "public, max-age=60"),
            ]

        def _safe_join(root: Path, url_path: str):
            path = (url_path or "/").split("?", 1)[0].split("#", 1)[0]
            path = unquote(path)
            while path.startswith("/"):
                path = path[1:]
            try:
                candidate = (root / path).resolve(strict=False)
                if str(candidate).startswith(str(root)):
                    return candidate
            except Exception:
                pass
            return None


        def _mk_response(status: int, hdrs_list: list[tuple[str, str]], body: bytes) -> Response:
            """
            Build a websockets.http11.Response in a version‑tolerant way:
            - Prefer the (status_code, reason_phrase, headers, body) signature (11.x+).
            - Fall back to (status_code, headers, body) if the older form is accepted.
            """
            # Minimal reason phrases (good enough for browsers / dev tools)
            reasons = {
                200: "OK",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                500: "Internal Server Error",
            }
            reason = reasons.get(int(status), "")

            # Ensure headers have the expected type; a list of pairs is also accepted,
            # but Headers(...) is safest across versions.
            hdrs = Headers(hdrs_list)

            try:
                # Newer signature: (status_code, reason_phrase, headers, body)
                return Response(int(status), reason, hdrs, body)
            except TypeError:
                # Older signature used in some releases: (status_code, headers, body)
                return Response(int(status), hdrs, body)


        # --- Modern handler: (connection, request) -> Response|None ---
        def _process_request_modern(connection, request):
            if not static_root:
                return None
            # Pass through real WS upgrades
            try:
                headers = getattr(request, "headers", {}) or {}
                upgrade = headers.get("Upgrade", headers.get("upgrade", "")) or ""
                conn = headers.get("Connection", headers.get("connection", "")) or ""
                if ("upgrade" in conn.lower()) and ("websocket" in upgrade.lower()):
                    return None
            except Exception:
                pass

            method = getattr(request, "method", "GET") or "GET"
            req_path = getattr(request, "path", "/") or "/"
            if method not in ("GET", "HEAD"):
                body = b"Method Not Allowed\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=req_path,
                    status=405,
                    target=None,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note="method-not-allowed",
                )
                return _mk_response(405, [("Allow", "GET, HEAD")] + _http_headers(405, len(body), "text/plain"), body)

            target = _safe_join(static_root, req_path)
            if target is None:
                body = b"Forbidden\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=req_path,
                    status=403,
                    target=None,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note="safe-join-rejected",
                )
                return _mk_response(403, _http_headers(403, len(body), "text/plain"), body)

            if target.is_dir():
                index = target / "index.html"
                if not (index.exists() and index.is_file()):
                    body = b"Not Found\n"
                    self._log_static_http_decision(
                        method=method,
                        req_path=req_path,
                        status=404,
                        target=target,
                        ctype="text/plain",
                        content_length=len(body),
                        body_length=len(body),
                        note="directory-without-index",
                    )
                    return _mk_response(404, _http_headers(404, len(body), "text/plain"), body)
                target = index

            if not target.exists() or not target.is_file():
                body = b"Not Found\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=req_path,
                    status=404,
                    target=target,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note="missing-file",
                )
                return _mk_response(404, _http_headers(404, len(body), "text/plain"), body)

            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            try:
                data = target.read_bytes()
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) static read error: {e!r}")
                body = b"Internal Server Error\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=req_path,
                    status=500,
                    target=target,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note=f"read-error={e!r}",
                )
                return _mk_response(500, _http_headers(500, len(body), "text/plain"), body)

            if method == "HEAD":
                self._log_static_http_decision(
                    method=method,
                    req_path=req_path,
                    status=200,
                    target=target,
                    ctype=ctype,
                    content_length=len(data),
                    body_length=0,
                    note="head-response",
                )
                self._schedule_static_http_debug_probes(
                    connection,
                    method=method,
                    req_path=req_path,
                    status=200,
                    target=target,
                    body_length=0,
                )
                return _mk_response(200, _http_headers(200, len(data), ctype), b"")
            self._log_static_http_decision(
                method=method,
                req_path=req_path,
                status=200,
                target=target,
                ctype=ctype,
                content_length=len(data),
                body_length=len(data),
                note="static-hit",
            )
            self._schedule_static_http_debug_probes(
                connection,
                method=method,
                req_path=req_path,
                status=200,
                target=target,
                body_length=len(data),
            )
            return _mk_response(200, _http_headers(200, len(data), ctype), data)

        # --- Legacy handler: (path, request_headers) -> (status, headers, body)|None ---
        def _process_request_legacy(path, request_headers):
            if not static_root:
                return None
            # Pass WS upgrade through (legacy servers often still call us)
            try:
                upgrade = request_headers.get("Upgrade", request_headers.get("upgrade", "")) or ""
                conn = request_headers.get("Connection", request_headers.get("connection", "")) or ""
                if ("upgrade" in conn.lower()) and ("websocket" in upgrade.lower()):
                    return None
            except Exception:
                pass

            # Legacy API doesn't expose method, assume GET
            method = "GET"
            target = _safe_join(static_root, path or "/")
            if target is None:
                body = b"Forbidden\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=path or "/",
                    status=403,
                    target=None,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note="safe-join-rejected",
                )
                return 403, _http_headers(403, len(body), "text/plain"), body

            if target.is_dir():
                index = target / "index.html"
                if not (index.exists() and index.is_file()):
                    body = b"Not Found\n"
                    self._log_static_http_decision(
                        method=method,
                        req_path=path or "/",
                        status=404,
                        target=target,
                        ctype="text/plain",
                        content_length=len(body),
                        body_length=len(body),
                        note="directory-without-index",
                    )
                    return 404, _http_headers(404, len(body), "text/plain"), body
                target = index

            if not target.exists() or not target.is_file():
                body = b"Not Found\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=path or "/",
                    status=404,
                    target=target,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note="missing-file",
                )
                return 404, _http_headers(404, len(body), "text/plain"), body

            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            try:
                data = target.read_bytes()
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) static read error: {e!r}")
                body = b"Internal Server Error\n"
                self._log_static_http_decision(
                    method=method,
                    req_path=path or "/",
                    status=500,
                    target=target,
                    ctype="text/plain",
                    content_length=len(body),
                    body_length=len(body),
                    note=f"read-error={e!r}",
                )
                return 500, _http_headers(500, len(body), "text/plain"), body

            self._log_static_http_decision(
                method=method,
                req_path=path or "/",
                status=200,
                target=target,
                ctype=ctype,
                content_length=len(data),
                body_length=len(data),
                note="static-hit",
            )
            return 200, _http_headers(200, len(data), ctype), data

        # --- One wrapper that adapts to either signature ---
        def _process_request(*args, **kwargs):
            try:
                if Response is not None and len(args) == 2 and hasattr(args[1], "path"):
                    return _process_request_modern(*args, **kwargs)  # (connection, request)
                if len(args) == 2 and isinstance(args[0], str):
                    return _process_request_legacy(*args, **kwargs)  # (path, headers)
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) process_request adapter error: {e!r}")
            return None
                
        # --------------- WS connection handler ---------------
        async def _handler(ws):
            
            path = getattr(ws, "path", getattr(getattr(ws, "request", None), "path", self._ws_path))
            self._log.debug(f"[WS-SESSION] ({self._probe_id}) HTTP path={path}")

            await self._on_accept(ws)
            # IMPORTANT: keep handler alive; otherwise server will close with 1000
            try:
                await ws.wait_closed()
            except Exception:
                pass

        # Start WebSocket server (+ static HTTP via process_request)
        #
        # NOTE: `open_timeout` isn't accepted by older websockets releases
        # (it gets forwarded to loop.create_server(), which raises TypeError
        # on Python 3.12). Only pass it when the installed websockets.serve
        # signature explicitly supports it.
        serve_kwargs = dict(
            host=self._listen_host,
            port=self._listen_port,
            ssl=ssl_ctx,
            subprotocols=subprotocols,
            max_size=self._ws_max_size,
            compression=self._ws_compression,
            ping_interval=None,  # we run our own RTT ping
            ping_timeout=None,
            write_limit=max(131072, self._ws_max_size or 0),  # allow larger HTTP responses to flush before close
            process_request=_process_request,  # <-- key: serve static before WS
        )
        try:
            import inspect
            if "open_timeout" in inspect.signature(websockets.serve).parameters:
                # static HTTP requests may stay non-WS during asset transfer
                serve_kwargs["open_timeout"] = None
        except Exception:
            pass

        self._server = await websockets.serve(_handler, **serve_kwargs)

        sockets = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
        self._log.info(
            f"[WS-SESSION] ({self._probe_id}) server listening on {sockets} path={self._ws_path}"
            + ("" if not static_root else f" (static={static_root})")
        )
                
    def _ensure_connect_once(self) -> None:
        if self._connecting_task is not None or not self._peer_tuple or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _connect(): await self._connect_to(host, port)
        self._connecting_task = self._loop.create_task(_connect())  # type: ignore

    def _start_reconnect_loop(self) -> None:
        if not self._peer_tuple or self._reconnect_task is not None or not self._run_flag:
            return
        host, port = self._peer_tuple
        async def _reconnect():
            delay = 0.5
            while self._run_flag:
                # If TCP writer exists, exit (RTT runtime will flip overlay state)
                if self._ws is not None:
                    return
                await self._connect_to(host, port)
                if self._ws is not None:
                    return
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return
                delay = min(delay * 2.0, 10.0)
        self._reconnect_task = self._loop.create_task(_reconnect())  # type: ignore

    async def _on_accept(self, ws) -> None:
        if not self._peer_tuple:
            peer_id = self._alloc_server_peer_id()
            ctx = {
                "peer_id": peer_id,
                "ws": ws,
                "tx_queue": asyncio.Queue(),
                "tx_task": None,
                "rx_task": None,
                "rtt": StreamRTT(log=self._log),
            }
            self._server_peers[peer_id] = ctx
            self._server_peer_by_ws_id[id(ws)] = peer_id
            self._configure_ws_socket(ws)
            peer = getattr(ws, "remote_address", None)
            sockname = getattr(ws, "local_address", None)
            self._log.info(f"[WS-SESSION] ({self._probe_id}) accept: peer_id={peer_id} local={sockname} peer={peer}")
            try:
                if isinstance(peer, tuple) and len(peer) >= 2:
                    self._peer_host, self._peer_port = peer[0], int(peer[1])
            except Exception:
                pass
            self._reset_counters()
            self._ensure_server_tx_task(ctx)
            ctx["rx_task"] = self._loop.create_task(self._rx_pump(ws=ws, peer_id=peer_id))  # type: ignore
            self._ws = ws
            self._rx_task = ctx["rx_task"]
            self._tx_task = ctx.get("tx_task")
            self._update_server_overlay_connected()
            if callable(self._on_peer_set_cb):
                try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                except Exception: pass
            return

        try:
            if self._ws:
                await self._ws.close()
        except Exception:
            pass

        self._ws = ws
        if self._disconnect_task:
            self._disconnect_task.cancel()
            self._disconnect_task = None
        self._configure_ws_socket(ws)
        peer = getattr(ws, "remote_address", None)
        sockname = getattr(ws, "local_address", None)
        self._log.info(f"[WS-SESSION] ({self._probe_id}) accept: local={sockname} peer={peer}")

        try:
            if isinstance(peer, tuple) and len(peer) >= 2:
                self._peer_host, self._peer_port = peer[0], int(peer[1])
        except Exception:
            pass

        self._reset_counters()
        self._rtt_rt.attach(self._send_ping_frame, on_state_change=self._on_rtt_state_change)
        self._log.debug(f"[WS/GUARD] ({self._probe_id}) on_accept ready; starting RX pump and RTT runtime")
        self._ensure_tx_task()
        self._rx_task = self._loop.create_task(self._rx_pump())      # type: ignore
        self._flush_early()

        if callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass

    async def _close_server_peer(self, peer_id: int) -> None:
        ctx = self._server_peers.pop(peer_id, None)
        if not ctx:
            return
        self._server_peer_by_ws_id.pop(id(ctx.get("ws")), None)
        self._server_unregister_peer_channels(peer_id)
        if callable(self._on_peer_disconnect_cb):
            try:
                self._on_peer_disconnect_cb(peer_id)
            except Exception as e:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) peer_disconnect callback err: {e!r}")
        tx_task = ctx.get("tx_task")
        if tx_task:
            tx_task.cancel()
        rx_task = ctx.get("rx_task")
        if rx_task and rx_task is not asyncio.current_task():
            rx_task.cancel()
        ws = ctx.get("ws")
        if self._ws is ws:
            self._ws = None
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        self._update_server_overlay_connected()

    async def _connect_to(self, host: str, port: int) -> None:
        if not self._run_flag:
            return
        try:
            import websockets
        except Exception:
            self._log.error("websockets package is required for WebSocketSession")
            self._connecting_task = None
            return

        ssl_ctx = None
        scheme = "wss" if self._use_tls else "ws"
        if self._use_tls:
            import ssl
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        uri_host = _strip_brackets(self._peer_name_host or host)
        if ":" in uri_host:
            uri_host = f"[{uri_host}]"
        uri_port = int(self._peer_name_port or port)
        uri = f"{scheme}://{uri_host}:{uri_port}{self._ws_path}"
        subprotocols = [self._ws_subprotocol] if self._ws_subprotocol else None
        connect_kwargs = {}
        proxy_sock = None
        proxy_target_host = _strip_brackets(self._peer_name_host or host)
        proxy_target_port = uri_port
        if self._proxy_feature_enabled():
            connect_kwargs["sock"] = proxy_sock = await self._open_ws_proxy_socket(proxy_target_host, proxy_target_port)
            if ssl_ctx is not None:
                connect_kwargs["server_hostname"] = proxy_target_host
        elif self._peer_name_host and (self._peer_name_host != host or uri_port != int(port)):
            connect_kwargs["host"] = host
            connect_kwargs["port"] = int(port)
            if ssl_ctx is not None:
                connect_kwargs["server_hostname"] = self._peer_name_host

        try:
            had_previous_connection = self.connection_epoch > 0
            if connect_kwargs.get("sock") is not None:
                proxy_endpoint = self._get_ws_proxy_endpoint(proxy_target_host, proxy_target_port)
                self._log.info(
                    f"[WS-SESSION] ({self._probe_id}) connecting to {uri} through proxy "
                    f"{proxy_endpoint[0]}:{proxy_endpoint[1]} auth={self._ws_proxy_auth}"
                )
            elif connect_kwargs:
                self._log.info(f"[WS-SESSION] ({self._probe_id}) connecting to {uri} via {host}:{int(port)}")
            else:
                self._log.info(f"[WS-SESSION] ({self._probe_id}) connecting to {uri}")
            if connect_kwargs.get("sock") is None:
                await self._load_default_http_page(
                    host=host,
                    port=int(port),
                    ssl_ctx=ssl_ctx,
                    server_hostname=connect_kwargs.get("server_hostname", self._peer_name_host or None),
                    host_header=uri_host.strip("[]"),
                )
            else:
                self._log.debug(f"[WS-SESSION] ({self._probe_id}) skipping HTTP preflight because proxy tunneling is active")
            t0 = time.perf_counter()
            ws = await websockets.connect(
                uri,
                ssl=ssl_ctx,
                subprotocols=subprotocols,
                max_size=self._ws_max_size,
                compression=self._ws_compression,
                ping_interval=None,    # we run our own RTT ping
                ping_timeout=None,
                **connect_kwargs,
            )
            dt = (time.perf_counter() - t0) * 1000.0
            local = getattr(ws, "local_address", None)
            remote = getattr(ws, "remote_address", None)
            self._log.info(f"[WS-SESSION] ({self._probe_id}) connected in {dt:.1f} ms local={local} peer={remote}")
            await self._on_accept(ws)
            if self._ws is ws:
                self.connection_epoch += 1
                self._log.debug("[WS-SESSION] (%s) transport epoch=%d", self._probe_id, self.connection_epoch)
                if had_previous_connection and callable(self._on_transport_epoch_change):
                    try:
                        self._on_transport_epoch_change(self.connection_epoch)
                    except Exception:
                        pass
            if self._peer_name_host:
                self._peer_host = self._peer_name_host
                self._peer_port = self._peer_name_port or int(port)
                if callable(self._on_peer_set_cb):
                    try: self._on_peer_set_cb(self._peer_host, self._peer_port)
                    except Exception: pass
        except Exception as e:
            if proxy_sock is not None:
                with contextlib.suppress(Exception):
                    proxy_sock.close()
            self._log.warning(f"[WS-SESSION] ({self._probe_id}) connect failed to {uri}: {e!r}")
        finally:
            self._connecting_task = None

    # --- counters / logging ----------------------------------------------------
    def _reset_counters(self) -> None:
        self._rx_bytes = self._tx_bytes = 0
        self._rx_crc32 = self._tx_crc32 = 0
        self._log.debug(f"[WS/CTR] ({self._probe_id}) reset (RX=0 CRC=0x00000000, TX=0 CRC=0x00000000)")

    def _log_counters(self, direction: str) -> None:
        self._log.log(
            self._ctr_log_level,
            f"[WS/CTR] ({self._probe_id}) {direction} "
            f"TX={self._tx_bytes} CRC32_TX=0x{self._tx_crc32:08x} "
            f"RX={self._rx_bytes} CRC32_RX=0x{self._rx_crc32:08x}"
        )

    def _bump_tx(self, data: bytes) -> None:
        self._tx_bytes += len(data)
        self._tx_crc32 = self._z.crc32(data, self._tx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    def _bump_rx(self, data: bytes) -> None:
        self._rx_bytes += len(data)
        self._rx_crc32 = self._z.crc32(data, self._rx_crc32) & 0xFFFFFFFF
        self._log_counters("UPDATE")

    # --- early buffer ----------------------------------------------------------
    def _buffer_early(self, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        now = time.time()
        if self._early_deadline and now > self._early_deadline:
            self._log.info(f"[WS/TX] ({self._probe_id}) early-buf TTL expired; discarding {self._early_buf_bytes}B")
            self._early_buf.clear()
            self._early_buf_bytes = 0
        self._early_deadline = now + self._early_ttl

        self._early_buf.append((bytes(wire), on_sent))
        self._early_buf_bytes += len(wire)
        while self._early_buf_bytes > self._early_max and self._early_buf:
            dropped, _ = self._early_buf.popleft()
            self._early_buf_bytes -= len(dropped)
            self._log.info(
                f"[WS/TX] ({self._probe_id}) early-buf capped: dropped={len(dropped)} keep={self._early_buf_bytes} cap={self._early_max}"
            )

    def _flush_early(self) -> None:
        if not self._early_buf or not self._ws:
            return
        try:
            pending = list(self._early_buf)
            self._log.info(
                f"[WS/TX] ({self._probe_id}) flushing early-buf frames={len(pending)} bytes={self._early_buf_bytes}"
            )
            for wire, on_sent in pending:
                self._schedule_send(wire, on_sent=on_sent)
        except Exception as e:
            self._log.info(f"[WS/TX] ({self._probe_id}) flush error: {e!r}")
        finally:
            self._early_buf.clear()
            self._early_buf_bytes = 0
            self._early_deadline = 0.0

    # --- sending helpers -------------------------------------------------------
    def _ensure_tx_task(self) -> None:
        if self._tx_task is not None or not self._ws:
            return

        async def _tx_loop():
            try:
                while True:
                    wire, on_sent = await self._tx_queue.get()
                    try:
                        if not self._ws:
                            continue
                        send_coro = self._ws.send(self._ws_payload_codec.encode(wire))
                        if self._ws_send_timeout_s > 0:
                            await asyncio.wait_for(send_coro, timeout=self._ws_send_timeout_s)
                        else:
                            await send_coro
                        self._bump_tx(wire)
                        if callable(on_sent):
                            try:
                                on_sent()
                            except Exception:
                                pass
                    except asyncio.TimeoutError:
                        self._log.warning(
                            f"[WS/TX] ({self._probe_id}) send timeout after {self._ws_send_timeout_s:.3f}s; forcing reconnect"
                        )
                        try:
                            await asyncio.wait_for(self._ws.close(), timeout=1.0)
                        except Exception:
                            pass
                    except Exception as e:
                        self._log.info(f"[WS/TX] ({self._probe_id}) send error: {e!r}")
                    finally:
                        self._tx_queue.task_done()
            except asyncio.CancelledError:
                return

        self._tx_task = self._loop.create_task(_tx_loop())  # type: ignore

    def _ensure_server_tx_task(self, ctx: dict) -> None:
        if ctx.get("tx_task") is not None or not ctx.get("ws"):
            return

        async def _tx_loop():
            q = ctx["tx_queue"]
            try:
                while True:
                    wire, on_sent = await q.get()
                    ws = ctx.get("ws")
                    try:
                        if ws is None:
                            continue
                        send_coro = ws.send(self._ws_payload_codec.encode(wire))
                        if self._ws_send_timeout_s > 0:
                            await asyncio.wait_for(send_coro, timeout=self._ws_send_timeout_s)
                        else:
                            await send_coro
                        self._bump_tx(wire)
                        if callable(on_sent):
                            try:
                                on_sent()
                            except Exception:
                                pass
                    except asyncio.TimeoutError:
                        self._log.warning(
                            f"[WS/TX] ({self._probe_id}) server peer_id={ctx['peer_id']} send timeout after {self._ws_send_timeout_s:.3f}s; closing peer"
                        )
                        await self._close_server_peer(ctx["peer_id"])
                        return
                    except Exception as e:
                        self._log.info(f"[WS/TX] ({self._probe_id}) server peer_id={ctx['peer_id']} send error: {e!r}")
                    finally:
                        q.task_done()
            except asyncio.CancelledError:
                return

        ctx["tx_task"] = self._loop.create_task(_tx_loop())  # type: ignore

    def _schedule_send(self, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        if not self._ws:
            return
        self._ensure_tx_task()
        self._tx_queue.put_nowait((bytes(wire), on_sent))

    def _schedule_server_send(self, ctx: dict, wire: bytes, on_sent: Optional[Callable[[], None]] = None) -> None:
        if not ctx.get("ws"):
            return
        self._ensure_server_tx_task(ctx)
        ctx["tx_queue"].put_nowait((bytes(wire), on_sent))

    def _configure_ws_socket(self, ws) -> None:
        try:
            transport = getattr(ws, "transport", None)
            sock = transport.get_extra_info("socket") if transport else None
            if not sock:
                return
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self._log.info(f"[WS-SESSION] ({self._probe_id}) SO_KEEPALIVE=1 set")
            user_timeout = self._ws_tcp_user_timeout_ms
            tcp_user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
            if user_timeout > 0 and tcp_user_timeout is not None:
                sock.setsockopt(socket.IPPROTO_TCP, tcp_user_timeout, user_timeout)
                self._log.info(
                    f"[WS-SESSION] ({self._probe_id}) TCP_USER_TIMEOUT={user_timeout}ms set"
                )
        except Exception as e:
            self._log.debug(f"[WS-SESSION] ({self._probe_id}) socket sockopt failed: {e!r}")


    def _notify_peer_tx(self, nbytes: int) -> None:
        if self._on_peer_tx:
            try:
                self._on_peer_tx(nbytes)
            except Exception:
                pass

    def _schedule_overlay_disconnect(self) -> None:
        if self._disconnect_task or not self._run_flag:
            return
        if self._ws_reconnect_grace_s <= 0:
            self._set_overlay_connected(False)
            return

        async def _delayed_disconnect():
            try:
                await asyncio.sleep(self._ws_reconnect_grace_s)
                if self._ws is None:
                    self._set_overlay_connected(False)
            except asyncio.CancelledError:
                return
            finally:
                self._disconnect_task = None

        self._disconnect_task = self._loop.create_task(_delayed_disconnect())  # type: ignore

    def _decode_ws_message(self, msg) -> Optional[bytes]:
        if isinstance(msg, str):
            try:
                return self._ws_payload_codec.decode(msg)
            except Exception as e:
                self._log.debug(f"[WS/RX] ({self._probe_id}) invalid {self._ws_payload_mode} text frame: {e!r}")
                return None
        try:
            return self._ws_payload_codec.decode(msg)
        except Exception as e:
            self._log.debug(f"[WS/RX] ({self._probe_id}) invalid {self._ws_payload_mode} frame: {e!r}")
            return None

    async def _load_default_http_page(
        self,
        *,
        host: str,
        port: int,
        ssl_ctx=None,
        server_hostname: Optional[str] = None,
        host_header: Optional[str] = None,
    ) -> None:
        request_host = host_header or server_hostname or host
        reader = None
        writer = None
        try:
            open_kwargs = {}
            if ssl_ctx is not None:
                open_kwargs["ssl"] = ssl_ctx
                open_kwargs["server_hostname"] = server_hostname or request_host
            reader, writer = await asyncio.open_connection(host=host, port=port, **open_kwargs)
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {request_host}\r\n"
                "Connection: close\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "User-Agent: ObstacleBridge-ws-preflight/1.0\r\n"
                "\r\n"
            ).encode("ascii")
            writer.write(request)
            await writer.drain()
            status_line = await reader.readline()
            if not status_line:
                raise RuntimeError("empty HTTP response")
            parts = status_line.decode("iso-8859-1", "replace").strip().split(" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            if status_code != 200:
                raise RuntimeError(f"unexpected HTTP status {status_code}")
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
            body = await reader.read(1)
            self._log.debug(
                f"[WS-SESSION] ({self._probe_id}) HTTP preflight GET / ok status={status_code} body_present={bool(body)}"
            )
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    def _decode_ws_message(self, msg) -> Optional[bytes]:
        if isinstance(msg, str):
            try:
                return self._ws_payload_codec.decode(msg)
            except Exception as e:
                self._log.debug(f"[WS/RX] ({self._probe_id}) invalid {self._ws_payload_mode} text frame: {e!r}")
                return None
        try:
            return self._ws_payload_codec.decode(msg)
        except Exception as e:
            self._log.debug(f"[WS/RX] ({self._probe_id}) invalid {self._ws_payload_mode} frame: {e!r}")
            return None

    async def _load_default_http_page(
        self,
        *,
        host: str,
        port: int,
        ssl_ctx=None,
        server_hostname: Optional[str] = None,
        host_header: Optional[str] = None,
    ) -> None:
        request_host = host_header or server_hostname or host
        reader = None
        writer = None
        try:
            open_kwargs = {}
            if ssl_ctx is not None:
                open_kwargs["ssl"] = ssl_ctx
                open_kwargs["server_hostname"] = server_hostname or request_host
            reader, writer = await asyncio.open_connection(host=host, port=port, **open_kwargs)
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {request_host}\r\n"
                "Connection: close\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "User-Agent: ObstacleBridge-ws-preflight/1.0\r\n"
                "\r\n"
            ).encode("ascii")
            writer.write(request)
            await writer.drain()
            status_line = await reader.readline()
            if not status_line:
                raise RuntimeError("empty HTTP response")
            parts = status_line.decode("iso-8859-1", "replace").strip().split(" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            if status_code != 200:
                raise RuntimeError(f"unexpected HTTP status {status_code}")
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
            body = await reader.read(1)
            self._log.debug(
                f"[WS-SESSION] ({self._probe_id}) HTTP preflight GET / ok status={status_code} body_present={bool(body)}"
            )
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    def _send_ping_frame(self, ping_payload: bytes) -> None:
        """
        Called by StreamRTTRuntime. Sends a PING control frame if WS exists.
        """
        if not self._peer_tuple:
            return
        if not self._ws:
            return

        body = bytes([self._K_PING]) + ping_payload

        # Guard log (tx_ns, echo_ns) for quick visibility
        try:
            if len(ping_payload) >= 16:
                tx_ns, echo_ns = struct.unpack(">QQ", ping_payload[:16])
                self._log.debug(f"[WS/GUARD] ({self._probe_id}) PING tx: tx_ns={tx_ns} echo_ns={echo_ns}")
        except Exception:
            pass

        self._schedule_send(body, on_sent=lambda: self._notify_peer_tx(len(body)))
        self._log.debug(f"[WS/TX] ({self._probe_id}) PING queued")
            
    def _send_pong_frame(self, echo_tx_ns: int) -> None:
        if not self._ws:
            return

        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)

        # Guard log
        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PONG tx: echo_tx_ns={echo_tx_ns}")

        self._schedule_send(body, on_sent=lambda: self._notify_peer_tx(len(body)))
        self._log.debug(f"[WS/TX] ({self._probe_id}) PONG queued")

    def _send_pong_frame_server(self, ctx: dict, echo_tx_ns: int) -> None:
        body = bytes([self._K_PONG]) + self._rtt.build_pong_bytes(echo_tx_ns)
        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PONG tx peer_id={ctx['peer_id']}: echo_tx_ns={echo_tx_ns}")
        self._schedule_server_send(ctx, body, on_sent=lambda: self._notify_peer_tx(len(body)))

    # --- RX pump ---------------------------------------------------------------
    async def _rx_pump(self, ws=None, peer_id: Optional[int] = None) -> None:
        client_mode = self._peer_tuple is not None
        active_ws = self._ws if ws is None else ws
        ctx = self._server_peers.get(peer_id) if (not client_mode and peer_id is not None) else None
        suffix = "" if peer_id is None else f" peer_id={peer_id}"
        self._log.debug(f"[WS/RX] ({self._probe_id}) pump start{suffix}")
        try:
            while True:
                if active_ws is None:
                    return
                msg = await active_ws.recv()  # type: ignore
                b = self._decode_ws_message(msg)
                if b is None:
                    continue
                if not b:
                    continue

                self._bump_rx(b)
                if self._on_peer_rx:
                    try: self._on_peer_rx(len(b))
                    except Exception: pass

                kind = b[0]
                payload = b[1:]

                if kind == self._K_APP:
                    if not client_mode and peer_id is not None:
                        payload = self._server_rewrite_inbound_app(peer_id, payload)
                    if self._on_app_from_peer_bytes:
                        try: self._on_app_from_peer_bytes(len(payload))
                        except Exception: pass
                    if callable(self._on_app):
                        try:
                            self._on_app(payload, peer_id=peer_id)
                        except TypeError:
                            try:
                                self._on_app(payload)
                            except Exception as e:
                                self._log.debug(f"[WS/RX] ({self._probe_id}) app callback err: {e!r}")
                        except Exception as e:
                            self._log.debug(f"[WS/RX] ({self._probe_id}) app callback err: {e!r}")

                elif kind == self._K_PING:
                    if len(payload) >= 16:
                        tx_ns, echo_ns = struct.unpack(">QQ", payload[:16])

                        # Guard log: we received PING (both original tx_ns and echo_ns)
                        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PING rx: tx_ns={tx_ns} echo_ns={echo_ns}")

                        if client_mode:
                            self._rtt.on_ping_received(tx_ns)
                            if echo_ns:
                                # Courtesy update
                                self._rtt.on_pong_received(echo_ns)
                            self._send_pong_frame(tx_ns)
                        elif ctx is not None:
                            ctx_rtt = ctx.get("rtt")
                            if ctx_rtt is not None:
                                ctx_rtt.on_ping_received(tx_ns)
                                if echo_ns:
                                    ctx_rtt.on_pong_received(echo_ns)
                            self._send_pong_frame_server(ctx, tx_ns)
                    else:
                        self._log.debug(f"[WS/RX] ({self._probe_id}) malformed PING len={len(payload)}")

                elif kind == self._K_PONG:
                    if client_mode and len(payload) >= 8:
                        (echo_tx_ns,) = struct.unpack(">Q", payload[:8])

                        # Take the sample before state flip for better logging
                        sample_ms = (time.monotonic_ns() - int(echo_tx_ns)) / 1e6

                        self._rtt.on_pong_received(echo_tx_ns)

                        # Guard log: PONG received with the measured RTT sample
                        self._log.debug(f"[WS/GUARD] ({self._probe_id}) PONG rx: echo_tx_ns={echo_tx_ns} sample_ms={sample_ms:.3f}")

                        # Fast nudge (state transition)
                        was = self._overlay_connected
                        now = self._rtt.is_connected()
                        if now != was:
                            self._set_overlay_connected(now)
                    else:
                        if client_mode:
                            self._log.debug(f"[WS/RX] ({self._probe_id}) malformed PONG len={len(payload)}")

                else:
                    self._log.debug(f"[WS/RX] ({self._probe_id}) unknown KIND=0x{kind:02x} n={len(b)}")

        except asyncio.CancelledError:
            self._log.debug(f"[WS/RX] ({self._probe_id}) cancelled")
            return
        except Exception as e:
            self._log.info(f"[WS/RX] ({self._probe_id}) pump error/close{suffix}: {e!r}")
        finally:
            if client_mode:
                try:
                    if self._ws:
                        await self._ws.close()   # type: ignore
                except Exception:
                    pass
                self._ws = None
                self._schedule_overlay_disconnect()
                if self._peer_tuple:
                    self._start_reconnect_loop()
            elif peer_id is not None:
                await self._close_server_peer(peer_id)
            self._log.debug(f"[WS/RX] ({self._probe_id}) pump stop{suffix}")

    # --- overlay state (RTT-driven) -------------------------------------------
    def _on_rtt_state_change(self, connected: bool) -> None:
        self._set_overlay_connected(connected)

    def _set_overlay_connected(self, v: bool) -> None:
        if self._overlay_connected == v:
            return
        self._overlay_connected = v
        mode = "RTT" if self._peer_tuple else "peer-count"
        self._log.info(f"[WS-SESSION] ({self._probe_id}) overlay -> {'CONNECTED' if v else 'DISCONNECTED'} ({mode})")
        if v and callable(self._on_peer_set_cb):
            try: self._on_peer_set_cb(self._peer_host, self._peer_port)
            except Exception: pass
        if callable(self._on_state):
            try: self._on_state(v)
            except Exception: pass

# -----------------------------------------------------------------------------


def now_ns() -> int:
    return time.monotonic_ns()


def _strip_brackets(host: str) -> str:
    if host and host.startswith('[') and host.endswith(']'):
        return host[1:-1]
    return host


def _peer_resolve_mode(args: argparse.Namespace) -> str:
    return str(getattr(args, "peer_resolve_family", "prefer-ipv6") or "prefer-ipv6")


def _host_ip_family(host: Optional[str]) -> int:
    host = _strip_brackets(host or "")
    if not host:
        return socket.AF_UNSPEC
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return socket.AF_UNSPEC
    return socket.AF_INET6 if addr.version == 6 else socket.AF_INET


def _bind_family_constraint(bind_host: Optional[str]) -> Optional[int]:
    host = _strip_brackets(bind_host or "")
    if not host or host == "::":
        return None
    fam = _host_ip_family(host)
    return fam if fam != socket.AF_UNSPEC else None


def _wildcard_host_for_family(family: int) -> str:
    return "::" if family == socket.AF_INET6 else "0.0.0.0"


def _localhost_fallback(resolve_mode: str) -> Optional[Tuple[str, int]]:
    mode = (resolve_mode or "").strip().lower()
    if mode == "ipv4":
        return ("127.0.0.1", socket.AF_INET)
    if mode == "ipv6":
        return ("::1", socket.AF_INET6)
    return None


def _prefer_unspec_listener_family() -> bool:
    """
    Python 3.9 needs explicit AF_INET/AF_INET6 in several asyncio listener paths.
    Newer runtimes handle AF_UNSPEC correctly, so we can let the stack decide.
    """
    return sys.version_info >= (3, 10)


def _listener_family_for_host(host: str) -> int:
    host = _strip_brackets(host or "")
    if _prefer_unspec_listener_family():
        return socket.AF_UNSPEC
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _resolve_peer_endpoint(
    host: str,
    port: int,
    *,
    resolve_mode: str = "prefer-ipv6",
    bind_host: Optional[str] = None,
    socktype: int = 0,
) -> Tuple[str, int, int]:
    host = _strip_brackets(host)
    if not host:
        raise RuntimeError("overlay peer requires a non-empty host name")

    family = _host_ip_family(host)
    if family != socket.AF_UNSPEC:
        if resolve_mode == "ipv4" and family != socket.AF_INET:
            raise RuntimeError(f"overlay peer {host!r} is not an IPv4 address")
        if resolve_mode == "ipv6" and family != socket.AF_INET6:
            raise RuntimeError(f"overlay peer {host!r} is not an IPv6 address")
        bind_family = _bind_family_constraint(bind_host)
        if bind_family is not None and bind_family != family:
            raise RuntimeError(
                f"overlay peer {host!r} resolves to family {family}, incompatible with bind {bind_host!r}"
            )
        return host, int(port), family

    lookup_family = socket.AF_UNSPEC
    if resolve_mode == "ipv4":
        lookup_family = socket.AF_INET
    elif resolve_mode == "ipv6":
        lookup_family = socket.AF_INET6

    try:
        infos = socket.getaddrinfo(host, int(port), family=lookup_family, type=socktype)
    except socket.gaierror as exc:
        localhost_fallback = _localhost_fallback(resolve_mode)
        if localhost_fallback and host.lower() == "localhost":
            fallback_host, fallback_family = localhost_fallback
            return fallback_host, int(port), fallback_family
        raise RuntimeError(f"Could not resolve overlay peer {host!r}: {exc}") from exc
    candidates: List[Tuple[str, int, int]] = []
    for fam, _socktype, _proto, _canonname, sockaddr in infos:
        if fam not in (socket.AF_INET, socket.AF_INET6):
            continue
        if not isinstance(sockaddr, tuple) or len(sockaddr) < 2:
            continue
        candidates.append((str(sockaddr[0]), int(sockaddr[1]), fam))

    if resolve_mode == "prefer-ipv6":
        candidates.sort(key=lambda item: 0 if item[2] == socket.AF_INET6 else 1)

    bind_family = _bind_family_constraint(bind_host)
    if bind_family is not None:
        matching = [item for item in candidates if item[2] == bind_family]
        if matching:
            candidates = matching
        else:
            fam_name = "IPv6" if bind_family == socket.AF_INET6 else "IPv4"
            raise RuntimeError(
                f"overlay peer {host!r} resolved, but no {fam_name} address is compatible with bind {bind_host!r}"
            )

    if not candidates:
        raise RuntimeError(f"Could not resolve overlay peer {host!r}")

    return candidates[0]


def _resolve_cli_peer(
    args: argparse.Namespace,
    *,
    peer_attr: str = "peer",
    peer_port_attr: str = "peer_port",
    bind_host: Optional[str] = None,
    socktype: int = 0,
) -> Optional[Tuple[str, int, int]]:
    peer = getattr(args, peer_attr, None)
    if not peer and peer_attr != "peer":
        peer = getattr(args, "peer", None)
    if not peer:
        return None
    peer_port = getattr(args, peer_port_attr, None)
    if (peer_port is None) and peer_port_attr != "peer_port":
        peer_port = getattr(args, "peer_port", 443)
    return _resolve_peer_endpoint(
        str(peer),
        int(peer_port if peer_port is not None else 443),
        resolve_mode=_peer_resolve_mode(args),
        bind_host=bind_host,
        socktype=socktype,
    )


def _overlay_cli_attrs(transport: str) -> Tuple[str, str, str, str]:
    transport = (transport or "myudp").strip().lower()
    if transport == "myudp":
        return ("udp_bind", "udp_peer", "udp_peer_port", "udp_own_port")
    if transport == "tcp":
        return ("tcp_bind", "tcp_peer", "tcp_peer_port", "tcp_own_port")
    if transport == "quic":
        return ("quic_bind", "quic_peer", "quic_peer_port", "quic_own_port")
    if transport == "ws":
        return ("ws_bind", "ws_peer", "ws_peer_port", "ws_own_port")
    return ("udp_bind", "udp_peer", "udp_peer_port", "udp_own_port")


def _has_configured_overlay_peer(args: argparse.Namespace, transport: Optional[str] = None) -> bool:
    if transport:
        _, peer_attr, _, _ = _overlay_cli_attrs(transport)
        return bool(getattr(args, peer_attr, None) or getattr(args, "peer", None))
    for proto in ("myudp", "tcp", "quic", "ws"):
        _, peer_attr, _, _ = _overlay_cli_attrs(proto)
        if getattr(args, peer_attr, None):
            return True
    return bool(getattr(args, "peer", None))


# ============================================================================
# Channel Multiplexer (shim between Runner and Session)
# ============================================================================


from dataclasses import dataclass
from typing import Literal, Optional, Tuple, Dict, Callable
import asyncio, time, zlib, struct, socket, logging


# ---------- Per-channel counters ----------

@dataclass
class _ChanCtr:
    msgs_in: int = 0
    msgs_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    crc_in: int = 0
    crc_out: int = 0

# ============================================================================
# ============================
# Multi-service ChannelMux (v3 control payloads)
# ============================
# Single source of truth for front-end servers:
# --own-servers "tcp,80,0.0.0.0,tcp,127.0.0.1,88 udp,16666,::,udp,127.0.0.1,16666"
#
# OPEN v4 binary payload (no backward compatibility):
# +------+--------+----------+----------+-----------+----------+
# | 'O4' | instance_id | conn_seq | svc_id | l_proto | bind_len | bind[...] | l_port | r_proto | host_len | host[...] | r_port |
# +------+--------+----------+----------+-----------+----------+
#   2B       u64         u32      u16      u8        u8        bytes       u16
#
# Features retained and extended:
# - Unconnected UDP server socket per service (AF_UNSPEC), serve many remote (addr,port)
# - UDP idle timeout 20s (no RX or TX) per (svc_id, addr) and per client-side chan
# - TCP backpressure per channel (size/time-based drain)
# - Per-channel counters (msgs/bytes + CRC32 in/out), detailed DEBUG logs
# - Safe read sizes (<= SAFE_TCP_READ == 65535-8)
# - Listener self-healing (_ensure_servers_task): auto-restart closed/broken servers
#
# Dependencies assumed available above in file:
#   Proto, MType, MUX_HDR, SAFE_TCP_READ, _pack_mux, _unpack_mux
#   plus imports: asyncio, logging, socket, struct, time, zlib


class ChannelMux:
    """Catalog-based multiplexer with multiple TCP/UDP servers and peer-side dynamic dialers."""
    ProtoName = Literal["tcp", "udp"]
    ServiceOrigin = Literal["local", "peer"]
    ServiceKey = Tuple[ServiceOrigin, int, int]  # (origin, peer_id, svc_id)

    class Proto(enum.IntEnum):
        UDP = 0
        TCP = 1

    class MType(enum.IntEnum):
        DATA = 0
        OPEN = 1  # TCP only
        CLOSE = 2  # TCP only
        REMOTE_SERVICES_SET_V1 = 3  # legacy control plane
        REMOTE_SERVICES_SET_V2 = 4  # control plane: peer installs listener catalog

    @dataclass(frozen=True)
    class ServiceSpec:
        svc_id: int
        l_proto: "ChannelMux.ProtoName"
        l_bind: str
        l_port: int
        r_proto: "ChannelMux.ProtoName"
        r_host: str
        r_port: int

    UDP_MIN_ID = 1
    UDP_MAX_ID = 65535
    TCP_MIN_ID = 1
    TCP_MAX_ID = 65535
    UDP_IDLE_S = 20.0

    # ---------------- CLI ----------------
    @staticmethod
    def register_cli(p) -> None:
        """Only the new catalog flag + optional mux TCP backpressure."""
        def _has(opt: str) -> bool:
            try: return any(opt in a.option_strings for a in p._actions)
            except Exception: return False
        if not _has('--own-servers'):
            p.add_argument(
                '--own-servers', nargs='*', default=None,
                help=("Space-separated service specs (client mode only): "
                      "'proto,listen_port,listen_bind,proto,host,port' (quoted). "
                      "Listener instances ignore --own-servers because multiple overlay peers make the target ambiguous. "
                      "Example: \"tcp,80,0.0.0.0,tcp,127.0.0.1,88 udp,16666,::,udp,127.0.0.1,16666\"")
            )
        if not _has('--remote-servers'):
            p.add_argument(
                '--remote-servers', nargs='*', default=None,
                help=("Space-separated service specs (client mode only, applied on connected peer): "
                      "'proto,listen_port,listen_bind,proto,host,port' (quoted). "
                      "Listener instances ignore --remote-servers because multiple overlay peers make the target ambiguous. "
                      "Example: \"tcp,80,0.0.0.0,tcp,127.0.0.1,88 udp,16666,::,udp,127.0.0.1,16666\"")
            )
        # Keep backpressure knobs (apply to local TCP writers we own)
        if not _has('--mux-tcp-bp-threshold'):
            p.add_argument('--mux-tcp-bp-threshold', type=int, default=1,
                           help='Mux TCP: size threshold (bytes) to trigger drain() (default 1).')
        if not _has('--mux-tcp-bp-latency-ms'):
            p.add_argument('--mux-tcp-bp-latency-ms', type=int, default=300,
                           help='Mux TCP: if > 0, drain writers after this ms when bytes pending.')
        if not _has('--mux-tcp-bp-poll-interval-ms'):
            p.add_argument('--mux-tcp-bp-poll-interval-ms', type=int, default=50,
                           help='Mux TCP: polling interval for time-based backpressure (ms).')

    @staticmethod
    def from_args(session, loop: asyncio.AbstractEventLoop, args,
                  on_local_rx_bytes: Optional[Callable[[int], None]] = None,
                  on_local_tx_bytes: Optional[Callable[[int], None]] = None) -> "ChannelMux":
        mux = ChannelMux(session, loop, on_local_rx_bytes, on_local_tx_bytes)
        # Parse catalog
        services = ChannelMux._parse_own_servers(getattr(args, 'own_servers', None))
        remote_services = ChannelMux._parse_remote_servers(getattr(args, 'remote_servers', None))
        active_transport = str(getattr(args, "overlay_transport", "myudp") or "myudp").split(",", 1)[0].strip().lower()
        listener_mode = not _has_configured_overlay_peer(args, active_transport)
        # Split channel-id space by role to avoid bidirectional OPEN collisions:
        # listener uses even ids, peer/client uses odd ids.
        mux._chan_id_start = 2 if listener_mode else 1
        mux._chan_id_stride = 2
        mux._next_udp_id = mux._chan_id_start
        mux._next_tcp_id = mux._chan_id_start
        if listener_mode and services:
            mux.log.info(
                "[MUX] listener mode detected: ignoring %d --own-servers entries; "
                "the listening peer must not expose ambiguous local services when multiple overlay peers connect",
                len(services),
            )
            services = []
        if listener_mode and remote_services:
            mux.log.info(
                "[MUX] listener mode detected: ignoring %d --remote-servers entries; "
                "the listening peer must not expose ambiguous local services when multiple overlay peers connect",
                len(remote_services),
            )
            remote_services = []
        #if not services:
         #   raise ValueError("No services defined. Provide --own-servers \"proto,port,bind,proto,host,port ...\"")
        for s in services:
            mux._local_services[("local", 0, s.svc_id)] = s
        mux._remote_services_requested = remote_services
        # Backpressure knobs
        try: mux._tcp_drain_threshold = int(getattr(args, 'mux_tcp_bp_threshold', 1))
        except Exception: pass
        try: mux._tcp_bp_latency_ms = int(getattr(args, 'mux_tcp_bp_latency_ms', 300))
        except Exception: mux._tcp_bp_latency_ms = 300
        try: mux._tcp_bp_poll_interval_s = float(getattr(args, 'mux_tcp_bp_poll_interval_ms', 50)) / 1000.0
        except Exception: mux._tcp_bp_poll_interval_s = 0.05
        return mux

    @staticmethod
    def _parse_own_servers(specs: Optional[list[str]]) -> list[ChannelMux.ServiceSpec]:
        """Parse --own-servers spec(s) into ServiceSpec list."""
        return ChannelMux._parse_service_specs(specs, "--own-servers")

    @staticmethod
    def _parse_remote_servers(specs: Optional[list[str]]) -> list[ChannelMux.ServiceSpec]:
        """Parse --remote-servers spec(s) into ServiceSpec list."""
        return ChannelMux._parse_service_specs(specs, "--remote-servers")

    @staticmethod
    def _parse_service_specs(specs: Optional[list[str]], arg_name: str) -> list[ChannelMux.ServiceSpec]:
        """Parse service spec(s) into ServiceSpec list."""
        import shlex
        if not specs:
            return []
        filtered_specs = [s for s in specs if isinstance(s, str) and s.strip()]
        if not filtered_specs:
            return []
        flat = " ".join(filtered_specs)
        tokens = shlex.split(flat)
        out: list[ChannelMux.ServiceSpec] = []
        sid = 1
        for tok in tokens:
            parts = [p.strip() for p in tok.split(",")]
            if len(parts) != 6:
                raise ValueError(f"{arg_name} item must have 6 comma-separated fields: {tok}")
            l_proto, l_port, l_bind, r_proto, r_host, r_port = parts
            l_proto = l_proto.lower()
            r_proto = r_proto.lower()
            if l_proto not in {"udp", "tcp"}:
                raise ValueError(f"{arg_name} local protocol must be udp or tcp: {tok}")
            if r_proto not in {"udp", "tcp"}:
                raise ValueError(f"{arg_name} remote protocol must be udp or tcp: {tok}")
            try:
                l_port_i = int(l_port)
                r_port_i = int(r_port)
            except Exception:
                raise ValueError(f"{arg_name} ports must be integers in 1..65535: {tok}")
            if not (1 <= l_port_i <= 65535) or not (1 <= r_port_i <= 65535):
                raise ValueError(f"{arg_name} ports must be integers in 1..65535: {tok}")
            out.append(ChannelMux.ServiceSpec(
                svc_id=sid,
                l_proto=l_proto,
                l_bind=l_bind,
                l_port=l_port_i,
                r_proto=r_proto,
                r_host=r_host.strip("[]"),
                r_port=r_port_i,
            ))
            sid += 1
        return out

    # -------------- lifecycle --------------
    def __init__(self, session, loop: asyncio.AbstractEventLoop,
                 on_local_rx_bytes: Optional[Callable[[int], None]] = None,
                 on_local_tx_bytes: Optional[Callable[[int], None]] = None):
        self.session = session
        self.log = logging.getLogger("channel_mux")
        DebugLoggingConfigurator.debug_logger_status(self.log)
        self.loop = loop
        self._on_local_rx = on_local_rx_bytes  # local->peer (overlay direction) counters hook
        self._on_local_tx = on_local_tx_bytes  # peer->local counters hook

        # Overlay state gate
        self._overlay_connected: bool = self.session.is_connected()
        self._accepting_enabled: bool = self._overlay_connected

        # Services
        self._local_services: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {}
        self._remote_services_requested: list[ChannelMux.ServiceSpec] = []
        self._peer_installed_services: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {}
        self._svc_tcp_servers: dict[ChannelMux.ServiceKey, asyncio.base_events.Server] = {}
        self._svc_udp_servers: dict[ChannelMux.ServiceKey, asyncio.DatagramTransport] = {}

        # Channel id allocators
        self._chan_id_start: int = 1
        self._chan_id_stride: int = 1
        self._next_udp_id: int = self.UDP_MIN_ID
        self._next_tcp_id: int = self.TCP_MIN_ID

        # UDP server-side maps
        # (svc_id, (host,port)) -> (chan, last_ts)
        self._udp_by_client: dict[tuple[ChannelMux.ServiceKey, tuple[str,int]], tuple[int,float]] = {}
        # chan -> (svc_key, (host,port))
        self._udp_by_chan: dict[int, tuple[ChannelMux.ServiceKey, tuple[str,int]]] = {}

        # UDP peer client-side transports
        self._udp_client_transports: dict[int, asyncio.DatagramTransport] = {}
        self._udp_client_last_ts: dict[int, float] = {}

        # UDP client early-buffer (per channel, preserves datagram boundaries)
        self._udp_client_pending: Dict[int, list[bytes]] = {}
        self._udp_client_pending_cap: int = 1024  # max queued datagrams per channel (tweak as needed)

        # TCP maps
        # chan -> (svc_id, writer)
        self._tcp_by_chan: dict[int, tuple[int, asyncio.StreamWriter]] = {}
        # writer -> (svc_id, chan)
        self._tcp_by_writer: dict[asyncio.StreamWriter, tuple[int,int]] = {}
        self._tcp_pending_data: dict[int, list[bytes]] = {}

        # Backpressure machinery (per TCP writer)
        self._tcp_send_locks: dict[int, asyncio.Lock] = {}
        self._tcp_backpressure_evt: dict[int, asyncio.Event] = {}
        self._tcp_backpressure_tasks: dict[int, asyncio.Task] = {}
        self._tcp_drain_threshold: int = 1
        self._tcp_bp_latency_ms: int = 300
        self._tcp_bp_poll_interval_s: float = 0.05

        # Rolling MUX counters (per (chan, proto))
        self._mux_counters: dict[tuple[int,int], int] = {}

        # MUX sender identity/epoch tracking
        self._mux_instance_id: int = random.getrandbits(64)
        self._mux_connection_seq: int = 1
        self._peer_mux_epochs: dict[int, tuple[int, int]] = {}
        # OPEN dedupe maps (full tuple keying)
        # key: (peer_id, chan_id, svc_id, l_proto_i, l_bind, l_port, r_proto_i, r_host, r_port)
        self._udp_open_key_by_chan: dict[int, tuple[int, int, int, int, str, int, int, str, int]] = {}
        self._udp_chan_by_open_key: dict[tuple[int, int, int, int, str, int, int, str, int], int] = {}
        self._tcp_open_key_by_chan: dict[int, tuple[int, int, int, str, int, int, str, int]] = {}
        self._tcp_chan_by_open_key: dict[tuple[int, int, int, str, int, int, str, int], int] = {}
        self._chan_owner_peer_id: dict[int, int] = {}

        # Per-channel stats (readable counters + CRC)
        self._chan_stats: dict[tuple[int,Proto], _ChanCtr] = {}

        # Tasks
        self._sweeper_task: Optional[asyncio.Task] = None
        self._ensure_task: Optional[asyncio.Task] = None

        self._SAFE_TCP_READ = 65535 - ChannelMux.MUX_HDR.size # (maximum app message size) - 8 (MUX header)

        # Dashboard interface
        self._udp_client_svc_id: Dict[int, int] = {}
        self._tcp_role_by_chan: Dict[int, str] = {}
        self._warn_dumped_channel_config: bool = False

        # Session payload hook
        try:
            self.session.set_on_app_payload(self.on_app_payload_from_peer)
            self.log.debug("[MUX] on_app_payload_from_peer wired")
        except Exception as e:
            self.log.error("[MUX] failed to wire on_app_payload_from_peer: %r", e)
        try:
            self.session.set_on_peer_disconnect(self.on_peer_disconnected)
            self.log.debug("[MUX] on_peer_disconnected wired")
        except Exception:
            pass

    # ---------- public counters ----------
    def udp_open_count(self) -> int:
        # Both sides: server mappings + live client transports
        return len(self._udp_by_chan) + len(self._udp_client_transports)

    def tcp_open_count(self) -> int:
        return len(self._tcp_by_chan)

    # OPEN v4 binary payload (no backward compatibility):
    # +------+-------------+----------+--------+----------+----------+-----------+----------+----------+----------+-----------+----------+
    # | 'O4' | instance_id | conn_seq | svc_id | l_proto  | bind_len | bind[...] | l_port   | r_proto  | host_len | host[...] | r_port   |
    # +------+-------------+----------+--------+----------+----------+-----------+----------+----------+----------+-----------+----------+
    #   2B       u64          u32       u16       u8         u8         bytes       u16        u8         u8         bytes       u16
    #
    # ---------------------------------------------------------------------------
    # MUX v2 wire header and helpers (module scope; used by ChannelMux)
    # ---------------------------------------------------------------------------
    # MUX v2 header: chan_id(2) | proto(1) | counter(2) | mtype(1) | data_len(2)
    MUX_HDR = struct.Struct(">HBHBH")
    
    def _pack_mux(self, chan_id: int, proto: ChannelMux.Proto, counter: int, mtype: ChannelMux.MType, data: bytes) -> bytes:
        if not (0 <= chan_id <= 0xFFFF):
            raise ValueError("chan_id out of range")
        if data is None:
            data = b""
        return ChannelMux.MUX_HDR.pack(chan_id, int(proto), counter & 0xFFFF, int(mtype), len(data)) + data

    def _unpack_mux(self, buf: bytes) -> Optional[Tuple[int, ChannelMux.Proto, int, ChannelMux.MType, memoryview]]:
        if not isinstance(buf, (bytes, bytearray, memoryview)) or len(buf) < ChannelMux.MUX_HDR.size:
            self.log.warning("[MUX] type or len error %i %i < %i", not isinstance(buf, (bytes, bytearray, memoryview)), len(buf), ChannelMux.MUX_HDR.size)
            return None
        mv = memoryview(buf)
        chan_id, proto, counter, mtype, dlen = ChannelMux.MUX_HDR.unpack(mv[:ChannelMux.MUX_HDR.size])
        if mv.nbytes < ChannelMux.MUX_HDR.size + dlen:
            self.log.warning("[MUX] unpack mux failed : too little data %i < %i", mv.nbytes, ChannelMux.MUX_HDR.size + dlen)
            return None
        try:
            return chan_id, ChannelMux.Proto(proto), counter, ChannelMux.MType(mtype), mv[ChannelMux.MUX_HDR.size:ChannelMux.MUX_HDR.size + dlen]
        except Exception as e:
            self.log.warning("[MUX] unpack mux failed : %r", e)
            return None

    # ---------- OPEN v4 payload ----------
    #  b"O4" + u64 instance_id + u32 connection_seq + u16 svc_id
    #        + u8 l_proto + u8 l_bind_len + l_bind + u16 l_port
    #        + u8 r_proto + u8 r_host_len + r_host + u16 r_port
    def _build_open_v4(self, spec: ChannelMux.ServiceSpec) -> bytes:
        lb = spec.l_bind.encode("utf-8", "ignore")
        hb = spec.r_host.encode("utf-8", "ignore")
        return (
            b"O4"
            + struct.pack(
                ">QIHBB",
                self._mux_instance_id & 0xFFFFFFFFFFFFFFFF,
                self._mux_connection_seq & 0xFFFFFFFF,
                spec.svc_id,
                1 if spec.l_proto == "tcp" else 0,
                len(lb),
            )
            + lb
            + struct.pack(
                ">HB",
                spec.l_port,
                1 if spec.r_proto == "tcp" else 0,
            )
            + struct.pack(">B", len(hb))
            + hb
            + struct.pack(">H", spec.r_port)
        )

    def _parse_open_v4(self, buf: bytes):
        if len(buf) < 2 + 8 + 4 + 2 + 1 + 1 + 2 + 1 + 1 + 2:
            return None
        if buf[0:2] != b"O4":
            return None
        instance_id, connection_seq, svc_id, l_proto, l_bind_len = struct.unpack(">QIHBB", buf[2:18])
        off = 18
        if len(buf) < off + l_bind_len + 2 + 1 + 1 + 2:
            return None
        l_bind = buf[off:off + l_bind_len].decode("utf-8", "ignore")
        off += l_bind_len
        l_port, r_proto = struct.unpack(">HB", buf[off:off + 3])
        off += 3
        (hlen,) = struct.unpack(">B", buf[off:off + 1])
        off += 1
        if len(buf) < off + hlen + 2:
            return None
        host = buf[off:off + hlen].decode("utf-8", "ignore")
        off += hlen
        (r_port,) = struct.unpack(">H", buf[off:off + 2])
        off += 2
        if off != len(buf):
            return None
        return instance_id, connection_seq, svc_id, l_proto, l_bind, l_port, r_proto, host, r_port

    # ---------- REMOTE_SERVICES_SET v2 payload ----------
    # b"RS2" + u64 instance_id + u32 connection_seq + u16 count + repeated:
    #   u16 svc_id + u8 l_proto + u8 l_bind_len + l_bind + u16 l_port
    #             + u8 r_proto + u8 r_host_len + r_host + u16 r_port
    def _encode_remote_services_set_v2(self, services: list["ChannelMux.ServiceSpec"]) -> bytes:
        out = bytearray(b"RS2")
        out += struct.pack(
            ">QIH",
            self._mux_instance_id & 0xFFFFFFFFFFFFFFFF,
            self._mux_connection_seq & 0xFFFFFFFF,
            len(services),
        )
        for s in services:
            lb = s.l_bind.encode("utf-8", "ignore")
            rh = s.r_host.encode("utf-8", "ignore")
            if len(lb) > 255 or len(rh) > 255:
                raise ValueError("REMOTE_SERVICES_SET_V2 host/bind too long")
            out += struct.pack(
                ">HBB",
                int(s.svc_id),
                1 if s.l_proto == "tcp" else 0,
                len(lb),
            )
            out += lb
            out += struct.pack(">HB", int(s.l_port), 1 if s.r_proto == "tcp" else 0)
            out += struct.pack(">B", len(rh))
            out += rh
            out += struct.pack(">H", int(s.r_port))
        return bytes(out)

    def _decode_remote_services_set_v2(self, payload: bytes) -> Optional[tuple[int, int, list["ChannelMux.ServiceSpec"]]]:
        if len(payload) < 17 or payload[:3] != b"RS2":
            return None
        try:
            off = 3
            instance_id, connection_seq, count = struct.unpack(">QIH", payload[off:off + 14])
            off += 14
            out: list[ChannelMux.ServiceSpec] = []
            for _ in range(int(count)):
                if off + 5 > len(payload):
                    return None
                svc_id, l_proto_i, l_len = struct.unpack(">HBB", payload[off:off + 4])
                off += 4
                if off + l_len + 4 > len(payload):
                    return None
                l_bind = payload[off:off + l_len].decode("utf-8", "ignore")
                off += l_len
                l_port, r_proto_i = struct.unpack(">HB", payload[off:off + 3])
                off += 3
                (r_len,) = struct.unpack(">B", payload[off:off + 1])
                off += 1
                if off + r_len + 2 > len(payload):
                    return None
                r_host = payload[off:off + r_len].decode("utf-8", "ignore")
                off += r_len
                (r_port,) = struct.unpack(">H", payload[off:off + 2])
                off += 2
                l_proto = "tcp" if int(l_proto_i) == 1 else "udp"
                r_proto = "tcp" if int(r_proto_i) == 1 else "udp"
                out.append(ChannelMux.ServiceSpec(
                    svc_id=int(svc_id),
                    l_proto=l_proto,
                    l_bind=l_bind,
                    l_port=int(l_port),
                    r_proto=r_proto,
                    r_host=r_host,
                    r_port=int(r_port),
                ))
            if off != len(payload):
                return None
            return instance_id, connection_seq, out
        except Exception:
            return None

    def _peer_epoch_is_new(self, peer_id: Optional[int], instance_id: int, connection_seq: int) -> bool:
        peer_key = int(peer_id or 0)
        prev = self._peer_mux_epochs.get(peer_key)
        if prev is None:
            self._peer_mux_epochs[peer_key] = (int(instance_id), int(connection_seq))
            return True
        prev_instance, prev_seq = prev
        if int(instance_id) == prev_instance and int(connection_seq) <= prev_seq:
            return False
        self._peer_mux_epochs[peer_key] = (int(instance_id), int(connection_seq))
        return True

    def _forget_udp_open_key(self, chan: int) -> None:
        key = self._udp_open_key_by_chan.pop(chan, None)
        if key is not None and self._udp_chan_by_open_key.get(key) == chan:
            self._udp_chan_by_open_key.pop(key, None)

    def _forget_tcp_open_key(self, chan: int) -> None:
        key = self._tcp_open_key_by_chan.pop(chan, None)
        if key is not None and self._tcp_chan_by_open_key.get(key) == chan:
            self._tcp_chan_by_open_key.pop(key, None)

    def _reset_peer_open_channels(self, peer_key: int) -> None:
        # UDP channels created from OPEN
        for key, chan in list(self._udp_chan_by_open_key.items()):
            if int(key[0]) != int(peer_key):
                continue
            tr = self._udp_client_transports.pop(chan, None)
            self._udp_client_last_ts.pop(chan, None)
            self._udp_client_pending.pop(chan, None)
            self._udp_client_svc_id.pop(chan, None)
            if tr:
                try:
                    tr.close()
                except Exception:
                    pass
            self._chan_owner_peer_id.pop(chan, None)
            self._forget_udp_open_key(chan)
            self.log.info("[MUX] peer=%s epoch reset -> drop UDP chan=%s", peer_key, chan)

        # TCP channels created from OPEN
        for key, chan in list(self._tcp_chan_by_open_key.items()):
            if int(key[0]) != int(peer_key):
                continue
            tup = self._tcp_by_chan.pop(chan, None)
            self._tcp_pending_data.pop(chan, None)
            self._tcp_role_by_chan.pop(chan, None)
            if tup:
                _, writer = tup
                self._tcp_by_writer.pop(writer, None)
                try:
                    writer.close()
                except Exception:
                    pass
            self._chan_owner_peer_id.pop(chan, None)
            self._forget_tcp_open_key(chan)
            self.log.info("[MUX] peer=%s epoch reset -> drop TCP chan=%s", peer_key, chan)
    # ---------- start/stop ----------
    async def start(self) -> None:
        self.log.info("[MUX] start; overlay_connected=%s accepting=%s", self._overlay_connected, self._accepting_enabled)
        effective_services = self._effective_services_by_id()
        if effective_services:
            specs = "; ".join(f"{s.svc_id}:{s.l_proto} {s.l_bind}:{s.l_port} -> {s.r_proto} {s.r_host}:{s.r_port}" for s in effective_services.values())
            self.log.info("[MUX] services: %s", specs)
        else:
            self.log.info("[MUX] services: (none)")
        self.log.info("[MUX] start; overlay_connected=%s accepting=%s", self._overlay_connected, self._accepting_enabled)
        if self._overlay_connected and self._accepting_enabled:
            await self._start_all_services()
            self._send_remote_services_catalog_if_any()
        self._sweeper_task = self.loop.create_task(self._udp_idle_sweeper())
        self._ensure_task = self.loop.create_task(self._ensure_servers_task())

    async def stop(self) -> None:
        self.log.info("[MUX] stopping")
        for t in (self._ensure_task, self._sweeper_task):
            if t:
                try: t.cancel()
                except Exception: pass
        self._ensure_task = self._sweeper_task = None
        await self._stop_all_services()
        await self._close_all_channels()
        await self._drop_peer_installed_services(peer_id=None)

    # ---------- overlay state ----------
    async def on_overlay_state(self, connected: bool):
        was_connected = self._overlay_connected
        self._overlay_connected = connected
        self.log.info("[MUX] overlay -> %s", "CONNECTED" if connected else "DISCONNECTED")
        if not connected:
            self._accepting_enabled = False
            await self._stop_all_services()
            await self._close_all_channels()
            return
        # Re-enable and (re)start
        if not was_connected:
            self._mux_connection_seq = (self._mux_connection_seq + 1) & 0xFFFFFFFF
        self._accepting_enabled = True
        await self._start_all_services()
        self._send_remote_services_catalog_if_any()

    async def on_transport_epoch_change(self, epoch: int) -> None:
        self.log.info("[MUX] transport epoch changed -> %s (hard resync)", epoch)
        self._mux_connection_seq = (self._mux_connection_seq + 1) & 0xFFFFFFFF
        await self._close_all_channels()
        if self._overlay_connected and self._accepting_enabled:
            await self._start_all_services()
        self._send_remote_services_catalog_if_any()

    # ---------- service lifecycle ----------
    async def _start_all_services(self):
        for svc_key, svc in self._effective_services_by_id().items():
            try:
                if svc.l_proto == "tcp" and svc_key not in self._svc_tcp_servers:
                    await self._start_tcp_server_for(svc, svc_key)
                elif svc.l_proto == "udp" and svc_key not in self._svc_udp_servers:
                    await self._start_udp_server_for(svc, svc_key)
            except Exception as e:
                self.log.warning("[MUX] service %s:%s start failed: %r", svc_key[0], svc.svc_id, e)

    async def _stop_all_services(self):
        # UDP first
        for sid, tr in list(self._svc_udp_servers.items()):
            try:
                self.log.info("[MUX] stopping UDP service %s", sid)
                tr.close()
            except Exception: pass
            self._svc_udp_servers.pop(sid, None)
        # TCP
        for sid, srv in list(self._svc_tcp_servers.items()):
            try:
                self.log.info("[MUX] stopping TCP service %s", sid)
                srv.close()
                await srv.wait_closed()
            except Exception: pass
            self._svc_tcp_servers.pop(sid, None)

    async def _close_all_channels(self):
        # TCP
        for chan, (sid, w) in list(self._tcp_by_chan.items()):
            try:
                self.log.info("[TCP/CLI] chan=%s svc=%s close (global shutdown)", chan, sid)
                w.close()
                aw = getattr(w, "wait_closed", None)
                if callable(aw): await aw()
            except Exception: pass
        self._tcp_by_chan.clear()
        self._tcp_by_writer.clear()
        self._tcp_pending_data.clear()
        self._tcp_role_by_chan.clear()
        self._tcp_open_key_by_chan.clear()
        self._tcp_chan_by_open_key.clear()
        self._chan_owner_peer_id.clear()
        # UDP server maps
        self._udp_by_client.clear()
        self._udp_by_chan.clear()
        # UDP client transports
        for chan, tr in list(self._udp_client_transports.items()):
            try: tr.close()
            except Exception: pass
        self._udp_client_transports.clear()
        self._udp_client_last_ts.clear()
        self._udp_client_pending.clear()
        self._udp_client_svc_id.clear()
        self._udp_open_key_by_chan.clear()
        self._udp_chan_by_open_key.clear()
        # Backpressure tasks
        for t in list(self._tcp_backpressure_tasks.values()):
            try: t.cancel()
            except Exception: pass
        self._tcp_backpressure_tasks.clear()
        self._tcp_backpressure_evt.clear()

    # ---------- UDP server (unconnected; multi-origin) ----------
    async def _start_udp_server_for(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
        parent = self
        class _UDPServer(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                parent._svc_udp_servers[svc_key] = transport
                parent.log.info("[UDP/SRV] service=%s:%s listening on %s:%s", svc_key[0], spec.svc_id, spec.l_bind, spec.l_port)
            def datagram_received(self, data: bytes, addr):
                parent._on_local_udp_datagram(spec, svc_key, data, addr)
            def error_received(self, exc):
                parent.log.info("[UDP/SRV] service=%s:%s transport error: %r", svc_key[0], spec.svc_id, exc)
            def connection_lost(self, exc):
                parent.log.info("[UDP/SRV] service=%s:%s transport lost: %r", svc_key[0], spec.svc_id, exc)
                # Remove so _ensure_servers_task will respawn
                parent._svc_udp_servers.pop(svc_key, None)

        family = _listener_family_for_host(spec.l_bind)
        await self.loop.create_datagram_endpoint(
            lambda: _UDPServer(),
            local_addr=(spec.l_bind, spec.l_port),
            family=family
        )

    def _on_local_udp_datagram(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey", data: bytes, addr: tuple[str,int]) -> None:
        if not (self._overlay_connected and self._accepting_enabled):
            self.log.debug(f"[NET] package dropping  : ")
            return
        now = time.time()
        key = (svc_key, addr)

        # --- NEW: resolve local server socket address once for this service ---
        srv_tr = self._svc_udp_servers.get(svc_key)
        l_sock = srv_tr.get_extra_info("sockname") if srv_tr else None
        l_ep = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else (spec.l_bind, int(spec.l_port))
        src = (addr[0], int(addr[1]))
        dst = l_ep

        if key not in self._udp_by_client:
            chan = self._alloc_udp_id()
            self._udp_by_client[key] = (chan, now)
            self._udp_by_chan[chan] = (svc_key, addr)
            if str(svc_key[0]) == "peer":
                self._chan_owner_peer_id[chan] = int(svc_key[1])
            self.log.debug("[UDP/SRV] learn %s -> chan=%s svc=%s:%s", addr, chan, svc_key[0], spec.svc_id)
            try:
                self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.OPEN, self._build_open_v4(spec))
            except Exception:
                pass
        else:
            chan, _ = self._udp_by_client[key]

        # --- Enhanced per-datagram log with endpoints ---
        ctr = self._ctr(ChannelMux.Proto.UDP, chan)
        ctr.msgs_in += 1
        ctr.bytes_in += len(data)
        try:
            self._log_conn("<-", "UDP", chan, data, src=src, dst=dst)
        except Exception as e:
            self.log.debug(f"[NET] logging failed : %r",e)
            pass

        # Touch activity & forward DATA to overlay
        self._udp_by_client[key] = (chan, now)
        self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.DATA, data)

    # ---------- UDP idle sweeper (both roles) ----------
    async def _udp_idle_sweeper(self):
        try:
            while True:
                await asyncio.sleep(1.0)
                now = time.time()
                # Server role mappings (per svc_id,addr)
                stale_srv: list[tuple[int, tuple[str,int]]] = []
                for key, (chan, ts) in list(self._udp_by_client.items()):
                    if (now - ts) >= self.UDP_IDLE_S:
                        stale_srv.append(key)
                for key in stale_srv:
                    chan, _ = self._udp_by_client.pop(key, (None, None))
                    if chan is None:
                        continue
                    self._udp_by_chan.pop(chan, None)
                    self.log.info("[UDP/SRV] chan=%s idle >= %.0fs -> CLOSE", chan, self.UDP_IDLE_S)
                    self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.CLOSE, b"")
                # Client role transports (per chan)
                stale_cli: list[int] = []
                for chan, ts in list(self._udp_client_last_ts.items()):
                    if (now - ts) >= self.UDP_IDLE_S:
                        stale_cli.append(chan)
                for chan in stale_cli:
                    tr = self._udp_client_transports.pop(chan, None)
                    self._udp_client_last_ts.pop(chan, None)
                    self._chan_owner_peer_id.pop(chan, None)
                    if tr:
                        try: tr.close()
                        except Exception: pass
                    self.log.info("[UDP/CLI] chan=%s idle >= %.0fs -> CLOSE", chan, self.UDP_IDLE_S)
                    self._send_mux(chan, ChannelMux.Proto.UDP, ChannelMux.MType.CLOSE, b"")
        except asyncio.CancelledError:
            return

    # ---------- Ensure servers task (self-healing) ----------
    async def _ensure_servers_task(self):
        try:
            while True:
                await asyncio.sleep(1.0)
                if not (self._overlay_connected and self._accepting_enabled):
                    continue
                for svc_key, spec in self._effective_services_by_id().items():
                    if spec.l_proto == "tcp":
                        srv = self._svc_tcp_servers.get(svc_key)
                        if srv is None or getattr(srv, "sockets", None) in (None, []):
                            self.log.info("[MUX] TCP service %s:%s ensure-listen (re)start", svc_key[0], spec.svc_id)
                            try:
                                await self._start_tcp_server_for(spec, svc_key)
                            except Exception as e:
                                self.log.info("[MUX] TCP service %s:%s restart failed: %r", svc_key[0], spec.svc_id, e)
                    else:
                        tr = self._svc_udp_servers.get(svc_key)
                        if tr is None:
                            self.log.info("[MUX] UDP service %s:%s ensure-listen (re)start", svc_key[0], spec.svc_id)
                            try:
                                await self._start_udp_server_for(spec, svc_key)
                            except Exception as e:
                                self.log.info("[MUX] UDP service %s:%s restart failed: %r", svc_key[0], spec.svc_id, e)
        except asyncio.CancelledError:
            return

    def _effective_services_by_id(self) -> dict["ChannelMux.ServiceKey", "ChannelMux.ServiceSpec"]:
        out: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {}
        out.update(self._local_services)
        out.update(self._peer_installed_services)
        return out

    def _send_remote_services_catalog_if_any(self) -> None:
        if not self._remote_services_requested:
            return
        try:
            payload = self._encode_remote_services_set_v2(self._remote_services_requested)
            self._send_mux(0, ChannelMux.Proto.UDP, ChannelMux.MType.REMOTE_SERVICES_SET_V2, payload)
            self.log.info("[MUX/CTRL] sent REMOTE_SERVICES_SET_V2 with %d service(s)", len(self._remote_services_requested))
        except Exception as e:
            self.log.warning("[MUX/CTRL] failed sending REMOTE_SERVICES_SET_V2: %r", e)

    async def _stop_listener_for_service_id(self, svc_key: "ChannelMux.ServiceKey", proto_name: str) -> None:
        if proto_name == "udp":
            tr = self._svc_udp_servers.pop(svc_key, None)
            if tr:
                try:
                    tr.close()
                except Exception:
                    pass
            return
        srv = self._svc_tcp_servers.pop(svc_key, None)
        if srv:
            try:
                srv.close()
                await srv.wait_closed()
            except Exception:
                pass

    async def _apply_peer_installed_services(self, services: list["ChannelMux.ServiceSpec"], peer_id: Optional[int]) -> None:
        owner_peer_id = int(peer_id or 0)
        new_map: dict[ChannelMux.ServiceKey, ChannelMux.ServiceSpec] = {
            ("peer", owner_peer_id, int(s.svc_id)): s for s in services
        }
        old_map = {k: v for k, v in self._peer_installed_services.items() if k[0] == "peer" and int(k[1]) == owner_peer_id}
        to_stop: set[ChannelMux.ServiceKey] = set()
        to_start: set[ChannelMux.ServiceKey] = set()

        for sid in set(old_map.keys()) - set(new_map.keys()):
            to_stop.add(sid)
        for sid in set(new_map.keys()) - set(old_map.keys()):
            to_start.add(sid)
        for sid in set(new_map.keys()) & set(old_map.keys()):
            if new_map[sid] != old_map[sid]:
                to_stop.add(sid)
                to_start.add(sid)

        for svc_key in set(old_map.keys()) - set(new_map.keys()):
            self._peer_installed_services.pop(svc_key, None)
        for svc_key, spec in new_map.items():
            self._peer_installed_services[svc_key] = spec

        for svc_key in sorted(to_stop):
            old = old_map.get(svc_key)
            if old:
                await self._stop_listener_for_service_id(svc_key, old.l_proto)

        if self._overlay_connected and self._accepting_enabled:
            for svc_key in sorted(to_start):
                spec = new_map.get(svc_key)
                if not spec:
                    continue
                try:
                    if spec.l_proto == "tcp" and svc_key not in self._svc_tcp_servers:
                        await self._start_tcp_server_for(spec, svc_key)
                    elif spec.l_proto == "udp" and svc_key not in self._svc_udp_servers:
                        await self._start_udp_server_for(spec, svc_key)
                except Exception as e:
                    self.log.warning("[MUX/CTRL] peer-installed service %s:%s start failed: %r", svc_key[0], spec.svc_id, e)

    async def _drop_peer_installed_services(self, peer_id: Optional[int]) -> None:
        if peer_id is None:
            to_stop = {k: v for k, v in self._peer_installed_services.items() if k[0] == "peer"}
        else:
            owner_peer_id = int(peer_id)
            to_stop = {
                k: v for k, v in self._peer_installed_services.items()
                if k[0] == "peer" and int(k[1]) == owner_peer_id
            }
        for svc_key, spec in list(to_stop.items()):
            self._peer_installed_services.pop(svc_key, None)
            await self._stop_listener_for_service_id(svc_key, spec.l_proto)

    def on_peer_disconnected(self, peer_id: int) -> None:
        self._peer_mux_epochs.pop(int(peer_id), None)
        self._reset_peer_open_channels(int(peer_id))
        try:
            self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_id))
        except Exception as e:
            self.log.debug("[MUX/CTRL] failed scheduling peer disconnect cleanup for peer_id=%s: %r", peer_id, e)

    # ---------- MUX send ----------
    def _send_mux(self, chan_id: int, proto: ChannelMux.Proto, mtype: ChannelMux.MType, data: bytes) -> None:
        if not self.session.is_connected():
            return
        # Enforce max application message size (MUX header + data <= 65535)
        if data is None:
            data = b""
        wire = self._pack_mux(chan_id, proto, self._next_ctr(chan_id, proto, mtype), mtype, data)
        if len(wire) > 65535:
            self.log.error("[MUX] drop oversized app message: %d bytes", len(wire))
            return
        # Local->peer counter hook
        if self._on_local_rx:
            try: self._on_local_rx(len(wire))
            except Exception: pass
        try:
            owner_peer_id = self._chan_owner_peer_id.get(int(chan_id))
            try:
                self.session.send_app(wire, peer_id=owner_peer_id)
            except TypeError:
                self.session.send_app(wire)
        except Exception as e:
            self.log.debug("[MUX] send_app error: %r", e)
        try:
            self._log_app_msg("->",wire)
        except Exception as e:
            self.log.debug("[MUX] logging error: %r", e)

    def _warning_with_channel_dump(self, msg: str, *args) -> None:
        self.log.warning(msg, *args)
        if self._warn_dumped_channel_config:
            return
        self._warn_dumped_channel_config = True
        try:
            self.log.warning(
                "[MUX/CFG] channel-config local=%d requested_remote=%d peer_installed=%d tcp_live=%d udp_srv_map=%d udp_cli_live=%d",
                len(self._local_services),
                len(self._remote_services_requested),
                len(self._peer_installed_services),
                len(self._tcp_by_chan),
                len(self._udp_by_chan),
                len(self._udp_client_transports),
            )
            self.log.warning(
                "[MUX/CFG] local_services=%s requested_remote=%s peer_installed=%s",
                [f"{k[0]}:{k[2]}:{v.l_proto}:{v.l_bind}:{v.l_port}->{v.r_proto}:{v.r_host}:{v.r_port}" for k, v in self._local_services.items()],
                [f"{s.svc_id}:{s.l_proto}:{s.l_bind}:{s.l_port}->{s.r_proto}:{s.r_host}:{s.r_port}" for s in self._remote_services_requested],
                [f"{k[0]}:{k[1]}:{k[2]}:{v.l_proto}:{v.l_bind}:{v.l_port}->{v.r_proto}:{v.r_host}:{v.r_port}" for k, v in self._peer_installed_services.items()],
            )
        except Exception as e:
            self.log.warning("[MUX/CFG] failed to dump channel-config: %r", e)

    def _next_ctr(self, chan_id: int, proto: ChannelMux.Proto, mtype: ChannelMux.MType) -> int:
        key = (chan_id, int(proto))
        if mtype == ChannelMux.MType.OPEN:
            self._mux_counters[key] = 0
            return 0
        prev = self._mux_counters.get(key, 0)
        nxt = (prev + 1) & 0xFFFF
        self._mux_counters[key] = nxt
        return nxt

    # ---------- MUX RX demux ----------
    def on_app_payload_from_peer(self, buf: bytes, peer_id: Optional[int] = None) -> bool:
        self.log.debug(f"[MUX] APP data receiving on session id=%x", id(self))
        try:
            self._log_app_msg("<-",buf)
        except Exception as e:
            self.log.debug("[MUX] logging error: %r", e)
        parsed = self._unpack_mux(buf)        
        if not parsed:
            self.log.warning(f"[APP] unpack failed len={len(buf)}: {buf[:16].hex().upper()}")
            return False
        chan_id, proto, counter, mtype, payload_mv = parsed
        payload = bytes(payload_mv)

        # Stats (peer->local bytes count for DATA only)
        if mtype == ChannelMux.MType.DATA and self._on_local_tx:
            try: self._on_local_tx(len(payload))
            except Exception: pass

        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2:
            decoded = self._decode_remote_services_set_v2(payload)
            if decoded is None:
                self.log.warning("[MUX/CTRL] invalid REMOTE_SERVICES_SET_V2 payload (%d bytes)", len(payload))
                return False
            instance_id, connection_seq, services = decoded
            peer_key = int(peer_id or 0)
            prev_epoch = self._peer_mux_epochs.get(peer_key)
            if not self._peer_epoch_is_new(peer_id, instance_id, connection_seq):
                self.log.debug("[MUX/CTRL] duplicate/replay REMOTE_SERVICES_SET_V2 peer_id=%s instance_id=%s connection_seq=%s", peer_key, instance_id, connection_seq)
            else:
                if prev_epoch is not None:
                    self._reset_peer_open_channels(peer_key)
                self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
            self.loop.create_task(self._apply_peer_installed_services(services, peer_id=peer_id))
            self.log.info(
                "[MUX/CTRL] received REMOTE_SERVICES_SET_V2 with %d service(s) from peer_id=%s instance_id=%s connection_seq=%s",
                len(services),
                peer_key,
                instance_id,
                connection_seq,
            )
            return True

        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V1:
            self.log.warning("[MUX/CTRL] unsupported REMOTE_SERVICES_SET_V1 payload (%d bytes)", len(payload))
            return False

        if proto == ChannelMux.Proto.UDP:
            self._rx_udp(chan_id, mtype, payload, peer_id=peer_id)
            return True

        if proto == ChannelMux.Proto.TCP:
            self._rx_tcp(chan_id, mtype, payload, peer_id=peer_id)
            return True

        return False

    # ---------- UDP RX path ----------
    def _rx_udp(self, chan_id: int, mtype: ChannelMux.MType, data: bytes, peer_id: Optional[int] = None) -> None:
        if mtype == ChannelMux.MType.OPEN:
            self._rx_udp_open(chan_id, data, peer_id=peer_id)
        elif mtype == ChannelMux.MType.DATA:
            self._rx_udp_data(chan_id, data)
        elif mtype == ChannelMux.MType.CLOSE:
            self._rx_udp_close(chan_id)
        else:
            self.log.warning(f"[APP] Unknwown mtype to dispatch UDP:{mtype}")


    def _rx_udp_open(self, chan: int, payload: bytes, peer_id: Optional[int] = None) -> None:
        p = self._parse_open_v4(payload)
        if not p:
            self.log.debug("[UDP/CLI] chan=%s OPEN parse failed", chan)
            return
        instance_id, connection_seq, svc_id, l_proto, l_bind, l_port, r_proto, host, r_port = p
        peer_key = int(peer_id or 0)
        prev_epoch = self._peer_mux_epochs.get(peer_key)
        if not self._peer_epoch_is_new(peer_id, instance_id, connection_seq):
            self.log.debug("[UDP/CLI] chan=%s duplicate/replay OPEN instance_id=%s connection_seq=%s", chan, instance_id, connection_seq)
        else:
            if prev_epoch is not None:
                self._reset_peer_open_channels(peer_key)
            self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
        self._udp_client_svc_id[chan] = int(svc_id)
        if int(l_proto) != int(ChannelMux.Proto.UDP):
            self.log.warning("[UDP/CLI] chan=%s OPEN declares non-UDP l_proto=%s (ignored)", chan, l_proto)
            return
        if int(r_proto) != int(ChannelMux.Proto.UDP):
            self.log.warning("[UDP/CLI] chan=%s OPEN requests non-UDP r_proto=%s (ignored)", chan, r_proto)
            return
        open_key = (peer_key, int(chan), int(svc_id), int(l_proto), str(l_bind), int(l_port), int(r_proto), str(host), int(r_port))
        existing_chan = self._udp_chan_by_open_key.get(open_key)
        if existing_chan is not None and existing_chan != chan:
            active = existing_chan in self._udp_client_transports
            if active:
                self.log.info(
                    "[UDP/CLI] duplicate OPEN ignored chan=%s existing_chan=%s key=%s:%s -> %s:%s",
                    chan, existing_chan, l_bind, l_port, host, r_port
                )
                return
            self._forget_udp_open_key(existing_chan)
        self._forget_udp_open_key(chan)
        self._udp_open_key_by_chan[chan] = open_key
        self._udp_chan_by_open_key[open_key] = chan
        if chan in self._udp_client_transports:
            return
        async def _mk():
            try:
                family = _listener_family_for_host(host)
                if family == socket.AF_INET6:
                    local_addr = ("::", 0)
                elif family == socket.AF_INET:
                    local_addr = ("0.0.0.0", 0)
                else:
                    local_addr = None
                tr, _ = await self.loop.create_datagram_endpoint(
                    lambda: self._UDPClientProtocol(self, chan),
                    local_addr=local_addr,
                    remote_addr=(host, int(r_port)),
                    family=family
                )
            except Exception as e:
                self.log.info("[UDP/CLI] chan=%s connect failed to %s:%s: %r", chan, host, r_port, e)
                self._forget_udp_open_key(chan)
                self._udp_client_svc_id.pop(chan, None)
                return

            try:
                self._udp_client_transports[chan] = tr  # type: ignore
                self._udp_client_last_ts[chan] = time.time()

                sockname = tr.get_extra_info("sockname")
                peername = tr.get_extra_info("peername")  # available on connected UDP sockets
                # Normalize to (ip, port) tuples (IPv6 tuples may have more fields)
                def _get_ip_port(x):
                    return (x[0], int(x[1])) if isinstance(x, tuple) and len(x) >= 2 else None
                l_ep = _get_ip_port(sockname)
                r_ep = _get_ip_port(peername) or (host, int(r_port))

                if l_ep and r_ep:
                    self.log.info("[UDP/CLI] chan=%s connected %s:%s -> %s:%s",
                                chan, l_ep[0], l_ep[1], r_ep[0], r_ep[1])
                else:
                    self.log.info("[UDP/CLI] chan=%s connected -> %s:%s", chan, host, r_port)
            except Exception as e:
                self.log.info("[UDP/CLI] chan=%s connect logging failed to %s:%s: %r", chan, host, r_port, e)

            # After creating the connected datagram endpoint and logging:
            try:
                self.log.info("[UDP/CLI] before-flush: chan=%s pending_len=%d",
                            chan, len(self._udp_client_pending.get(chan, [])))    
                pend = self._udp_client_pending.pop(chan, [])
                if pend:
                    try:
                        for idx, pkt in enumerate(pend, 1):
                            tr.sendto(pkt)
                        self.log.info("[UDP/CLI] chan=%s flushed %d early UDP datagram(s)", chan, len(pend))
                    except Exception as e:
                        self.log.info("[UDP/CLI] chan=%s early-buffer flush failed: %r", chan, e)
                else:
                        self.log.info("[UDP/CLI] chan=%s no flushing of early UDP datagram(s) was required ... skipped", chan)
            except Exception as e:
                self.log.info("[UDP/CLI] chan=%s flushing failed to %s:%s: %r", chan, host, r_port, e)


        self.loop.create_task(_mk())

    # --- ChannelMux._rx_udp_data (drop-in replacement) ---
    def _rx_udp_data(self, chan: int, data: bytes) -> None:
        """
        UDP RX demux:
        1) If this chan is mapped to a local UDP 'client' (server role), sendto(addr) and RETURN.
        2) Else, if there is a connected client-side UDP transport, sendto(peer) and RETURN.
        3) Else, queue in the early buffer for this chan (preserve datagram boundaries).
        """
        ctr = self._ctr(ChannelMux.Proto.UDP, chan)
        ctr.msgs_in += 1
        ctr.bytes_in += len(data)        
        # --- 1) Server-side mapping: remote -> original local sender
        svc = self._udp_by_chan.get(chan)
        if svc is not None:
            svc_key, addr = svc
            srv_tr = self._svc_udp_servers.get(svc_key)
            if srv_tr:
                try:
                    ctr.msgs_out += 1
                    ctr.bytes_out += len(data)
                    srv_tr.sendto(data, addr)
                    # Touch activity
                    key = (svc_key, addr)
                    if key in self._udp_by_client:
                        self._udp_by_client[key] = (chan, time.time())
                except Exception as e:
                    self.log.debug("[UDP/SRV] chan=%s sendto error: %r", chan, e)
                # Best-effort wire log
                try:
                    l_sock = srv_tr.get_extra_info("sockname")
                    src = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None
                    dst = (addr[0], int(addr[1]))
                    self._log_conn("->", "UDP/SRV", chan, data, src=src, dst=dst)
                except Exception as e:
                    self.log.debug(f"[NET] logging failed : %r",e)
                    pass
            return  # <-- prevent falling into client branch

        # --- 2) Client-side: overlay -> connected remote endpoint
        tr = self._udp_client_transports.get(chan)
        if tr is None:
            # 3) Not connected yet: early buffer (cap + datagram boundaries)
            q = self._udp_client_pending.setdefault(chan, [])
            if len(q) < self._udp_client_pending_cap:
                q.append(bytes(data))
                self.log.info(
                    "[UDP/CLI] chan=%s DATA not routed yet (no client transport); early-buffered %dB (pending=%d)",
                    chan,
                    len(data),
                    len(q),
                )
            else:
                self._warning_with_channel_dump(
                    "[UDP/CLI] chan=%s DATA routing failed (no client transport, early-buffer full cap=%d) -> drop %dB",
                    chan,
                    self._udp_client_pending_cap,
                    len(data),
                )
            return

        # We have a transport: send and log
        try:
            ctr.msgs_out += 1
            ctr.bytes_out += len(data)
            tr.sendto(data)
            self._udp_client_last_ts[chan] = time.time()
        except Exception as e:
            self.log.debug("[UDP/CLI] chan=%s send error: %r", chan, e)
            return

        try:
            l_sock = tr.get_extra_info("sockname")
            p_sock = tr.get_extra_info("peername")
            src = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None
            dst = (p_sock[0], int(p_sock[1])) if isinstance(p_sock, tuple) and len(p_sock) >= 2 else None
            # NOTE: pass "UDP*" (no trailing colon) to avoid "UDP*::1" tag
            self._log_conn("->", "UDP/CLI", chan, data, src=src, dst=dst)
        except Exception as e:
            self.log.debug(f"[NET] logging failed : %r",e)
            pass           

    def _rx_udp_close(self, chan: int) -> None:
        # Client role cleanup
        tr = self._udp_client_transports.pop(chan, None)
        self._udp_client_last_ts.pop(chan, None)
        self._chan_stats.pop((chan, ChannelMux.Proto.UDP), None)
        self._chan_owner_peer_id.pop(chan, None)
        if tr:
            try: tr.close()
            except Exception: pass
        # Server role cleanup
        self._udp_client_svc_id.pop(chan, None)
        self._udp_client_pending.pop(chan, None)
        self._forget_udp_open_key(chan)
        svc_addr = self._udp_by_chan.pop(chan, None)
        if svc_addr:
            svc_key, addr = svc_addr
            self._udp_by_client.pop((svc_key, addr), None)        
        self.log.info("[UDP] chan=%s CLOSE => local teardown", chan)

    class _UDPClientProtocol(asyncio.DatagramProtocol):
        def __init__(self, parent: "ChannelMux", chan: int):
            self.parent = parent
            self.chan = chan
            self.transport: Optional[asyncio.DatagramTransport] = None

        def connection_made(self, transport):
            self.transport = transport  # keep for sockname/peername

        def datagram_received(self, data: bytes, addr):
            ctr = self.parent._ctr(ChannelMux.Proto.UDP, self.chan)
            ctr.msgs_out += 1
            ctr.bytes_out += len(data)
            # remote -> overlay
            try:
                # Resolve endpoints for logging
                l_sock = self.transport.get_extra_info("sockname") if self.transport else None
                p_sock = self.transport.get_extra_info("peername") if self.transport else None
                src = (addr[0], int(addr[1])) if isinstance(addr, tuple) and len(addr) >= 2 else (
                    (p_sock[0], int(p_sock[1])) if isinstance(p_sock, tuple) and len(p_sock) >= 2 else None)
                dst = (l_sock[0], int(l_sock[1])) if isinstance(l_sock, tuple) and len(l_sock) >= 2 else None

                self.parent._log_conn("<-", "UDP/CLI:", self.chan, data, src=src, dst=dst)
            except Exception as e:
                self.log.debug(f"[NET] logging failed : %r",e)
                pass
            self.parent._send_mux(self.chan, ChannelMux.Proto.UDP, ChannelMux.MType.DATA, data)
            self.parent._udp_client_last_ts[self.chan] = time.time()

        def error_received(self, exc):
            self.parent.log.debug("[UDP/CLI] chan=%s error: %r", self.chan, exc)

        def connection_lost(self, exc):
            self.parent.log.info("[UDP/CLI] chan=%s connection_lost: %r", self.chan, exc)
            self.parent._udp_client_transports.pop(self.chan, None)
            self.parent._udp_client_last_ts.pop(self.chan, None)
            self.parent._forget_udp_open_key(self.chan)

    # ---------- TCP server ----------
    async def _start_tcp_server_for(self, spec: ChannelMux.ServiceSpec, svc_key: "ChannelMux.ServiceKey"):
        async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            if not self._overlay_connected or not self._accepting_enabled:
                try:
                    writer.close()
                    await getattr(writer, "wait_closed", lambda: asyncio.sleep(0))()
                except Exception:
                    pass
                return

            chan = self._alloc_tcp_id()
            peer = writer.get_extra_info("peername")
            self._tcp_by_chan[chan] = (spec.svc_id, writer)
            self._tcp_by_writer[writer] = (spec.svc_id, chan)
            self._tcp_role_by_chan[chan] = "server"      
            if str(svc_key[0]) == "peer":
                self._chan_owner_peer_id[chan] = int(svc_key[1])
            self.log.info(
                "[TCP/SRV] accept peer=%s -> chan=%s svc=%s map_size=%s",
                peer,
                chan,
                spec.svc_id,
                len(self._tcp_by_chan),
            )

            # Install backpressure worker
            self._ensure_backpressure_task(chan, writer)

            # Send OPEN v4 (peer dials r_proto/r_host/r_port with full tuple metadata)
            try:
                self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.OPEN, self._build_open_v4(spec))
            except Exception:
                pass

            # Pump outbound (local->overlay)
            async def _pump():
                try:
                    while True:
                        data = await reader.read(self._SAFE_TCP_READ)  # <= 65535-8
                        if not data:
                            break

                        # --- NEW: connection-level log (local TCP -> overlay) ---
                        try:
                            l_ep, r_ep = self._tcp_endpoints(writer)
                            # src = remote TCP peer; dst = our local listening endpoint
                            src = r_ep
                            dst = l_ep
                            self._log_conn("<-", "TCP", chan, data, src=src, dst=dst)
                        except Exception as e:
                            self.log.debug(f"[NET] logging failed : %r",e)
                            pass

                        # ---------------------------------------------------------
                        ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                        ctr.msgs_in += 1
                        ctr.bytes_in += len(data)
                        self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.DATA, data)
                        self.log.debug("[TCP/SRV] chan=%s local->overlay %dB", chan, len(data))
                except Exception as e:
                    self.log.info("[TCP/SRV] chan=%s pump error: %r", chan, e)
                finally:
                    self.log.info("[TCP/SRV] chan=%s EOF -> CLOSE (srv teardown begin)", chan)
                    self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.CLOSE, b"")
                    try:
                        writer.close()
                        await getattr(writer, "wait_closed", lambda: asyncio.sleep(0))()
                    except Exception:
                        pass
                    self._tcp_by_writer.pop(writer, None)
                    self._tcp_by_chan.pop(chan, None)
                    self._chan_owner_peer_id.pop(chan, None)
                    self._forget_tcp_open_key(chan)
                    self.log.info("[TCP/SRV] chan=%s CLOSE teardown complete map_size=%s", chan, len(self._tcp_by_chan))

            self.loop.create_task(_pump())
        try:
            family = _listener_family_for_host(spec.l_bind)
            srv = await asyncio.start_server(_handle, host=spec.l_bind, port=spec.l_port, family=family)
        except TypeError:
            srv = await asyncio.start_server(_handle, host=spec.l_bind, port=spec.l_port)

        self._svc_tcp_servers[svc_key] = srv
        sockets = ", ".join(str(s.getsockname()) for s in (srv.sockets or []))
        self.log.info("[TCP/SRV] service=%s:%s listening on %s", svc_key[0], spec.svc_id, sockets)


    # ---------- TCP RX path ----------
    def _rx_tcp(self, chan: int, mtype: ChannelMux.MType, data: bytes, peer_id: Optional[int] = None) -> None:
        if mtype == ChannelMux.MType.OPEN:
            # Peer instructs us to dial TCP to (host,port)
            p = self._parse_open_v4(data)
            if not p:
                self.log.debug("[TCP/CLI] chan=%s OPEN parse failed", chan)
                return
            instance_id, connection_seq, svc_id, l_proto, l_bind, l_port, r_proto, host, r_port = p
            peer_key = int(peer_id or 0)
            prev_epoch = self._peer_mux_epochs.get(peer_key)
            epoch_is_new = self._peer_epoch_is_new(peer_id, instance_id, connection_seq)
            self.log.info(
                "[TCP/CLI] OPEN recv chan=%s peer=%s iid=%s seq=%s svc=%s l=%s:%s r=%s:%s epoch_is_new=%s prev_epoch=%s",
                chan,
                peer_key,
                instance_id,
                connection_seq,
                svc_id,
                l_bind,
                l_port,
                host,
                r_port,
                epoch_is_new,
                prev_epoch,
            )
            if epoch_is_new:
                if prev_epoch is not None:
                    self._reset_peer_open_channels(peer_key)
                self.loop.create_task(self._drop_peer_installed_services(peer_id=peer_key))
            else:
                self.log.debug(
                    "[TCP/CLI] duplicate/replay OPEN epoch observed but not treated as channel duplicate chan=%s iid=%s seq=%s",
                    chan,
                    instance_id,
                    connection_seq,
                )
            if int(l_proto) != int(ChannelMux.Proto.TCP):
                self.log.warning("[TCP/CLI] chan=%s OPEN declares non-TCP l_proto=%s", chan, l_proto)
                return
            if int(r_proto) != int(ChannelMux.Proto.TCP):
                self.log.warning("[TCP/CLI] chan=%s OPEN requests non-TCP r_proto=%s", chan, r_proto)
                return
            open_key = (peer_key, int(svc_id), int(l_proto), str(l_bind), int(l_port), int(r_proto), str(host), int(r_port))
            self._forget_tcp_open_key(chan)
            self._tcp_open_key_by_chan[chan] = open_key
            self._tcp_chan_by_open_key[open_key] = chan
            self.log.info(
                "[TCP/CLI] OPEN channel identity bind chan=%s key=%s:%s->%s:%s key_map_size=%s",
                chan,
                l_bind,
                l_port,
                host,
                r_port,
                len(self._tcp_chan_by_open_key),
            )
            if chan in self._tcp_by_chan:
                self.log.info("[TCP/CLI] chan=%s OPEN ignored because chan already connected", chan)
                return

            async def _dial():
                try:
                    reader = asyncio.StreamReader()
                    protocol = asyncio.StreamReaderProtocol(reader)
                    self.log.info("[TCP/CLI] chan=%s connecting -> %s:%s", chan, host, r_port)
                    transport, _ = await self.loop.create_connection(lambda: protocol, host=host, port=int(r_port))
                    writer = asyncio.StreamWriter(transport, protocol, reader, self.loop)
                    self._tcp_by_chan[chan] = (svc_id, writer)
                    self._tcp_by_writer[writer] = (svc_id, chan)
                    self._tcp_role_by_chan[chan] = "client"
                    pending = self._tcp_pending_data.pop(chan, [])
                    for buf in pending:
                        try:
                            writer.write(buf)
                            ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                            ctr.msgs_out += 1
                            ctr.bytes_out += len(buf)
                            self._maybe_signal_backpressure(chan, writer)
                            self.log.debug("[TCP/CLI] chan=%s flushed pending %dB", chan, len(buf))
                        except Exception as e:
                            self.log.info("[TCP/CLI] chan=%s pending flush error: %r", chan, e)
                            break

                    # Backpressure worker
                    self._ensure_backpressure_task(chan, writer)

                    # Start RX pump: remote->overlay
                    async def _rx():
                        try:
                            while True:
                                buf = await reader.read(self._SAFE_TCP_READ)
                                if not buf:
                                    break

                                # --- NEW: connection-level log (remote TCP -> overlay) ---
                                try:
                                    l_ep, r_ep = self._tcp_endpoints(writer)
                                    # For a client-dialed socket, src = remote endpoint, dst = our local endpoint
                                    src = r_ep
                                    dst = l_ep
                                    self._log_conn("<-", "TCP", chan, buf, src=src, dst=dst)
                                except Exception as e:
                                    self.log.debug(f"[NET] logging failed : %r",e)
                                    pass
                                # ---------------------------------------------------------
                                ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                                ctr.msgs_in += 1
                                ctr.bytes_in += len(buf)
                                self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.DATA, buf)
                                self.log.debug("[TCP/CLI] chan=%s remote->overlay %dB", chan, len(buf))
                        except Exception as e:
                            self.log.info("[TCP/CLI] chan=%s rx error: %r", chan, e)
                        finally:
                            self.log.info("[TCP/CLI] chan=%s EOF -> CLOSE", chan)
                            self._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.CLOSE, b"")
                            try:
                                writer.close()
                                await getattr(writer, "wait_closed", lambda: asyncio.sleep(0))()
                            except Exception:
                                pass
                            self._tcp_by_writer.pop(writer, None)
                            self._tcp_by_chan.pop(chan, None)
                            self._forget_tcp_open_key(chan)
                            self.log.info("[TCP/CLI] chan=%s CLOSE teardown complete map_size=%s", chan, len(self._tcp_by_chan))

                    self.loop.create_task(_rx())
                    # (No early buffer on ChannelMux TCP paths)
                except Exception as e:
                    self.log.info("[TCP/CLI] chan=%s connect failed: %r", chan, e)
                    self._tcp_pending_data.pop(chan, None)
                    self._forget_tcp_open_key(chan)

            self.loop.create_task(_dial())
            return

        # DATA to local TCP writer (overlay -> local)
        if mtype == ChannelMux.MType.DATA:
            open_key = self._tcp_open_key_by_chan.get(chan)
            role = self._tcp_role_by_chan.get(chan)
            pending = len(self._tcp_pending_data.get(chan, []))
            self.log.debug(
                "[TCP] chan=%s DATA arrival check: writer_ready=%s role=%s pending=%s open_bound=%s tcp_map_size=%s",
                chan,
                chan in self._tcp_by_chan,
                role,
                pending,
                open_key is not None,
                len(self._tcp_by_chan),
            )
            tup = self._tcp_by_chan.get(chan)
            if not tup:
                self._tcp_pending_data.setdefault(chan, []).append(data)
                self._warning_with_channel_dump(
                    "[TCP] chan=%s DATA not routed yet (writer not ready); buffered %dB (pending=%d)",
                    chan,
                    len(data),
                    len(self._tcp_pending_data.get(chan, [])),
                )
                return
            svc_id, writer = tup
            try:
                writer.write(data)

                # --- NEW: connection-level log (overlay -> local TCP) ---
                try:
                    l_ep, r_ep = self._tcp_endpoints(writer)
                    # src = our local TCP endpoint, dst = remote peer
                    self._log_conn("->", "TCP", chan, data, src=l_ep, dst=r_ep)
                except Exception as e:
                    self.log.debug(f"[NET] logging failed : %r",e)
                    pass

                # --------------------------------------------------------
                ctr = self._ctr(ChannelMux.Proto.TCP, chan)
                ctr.msgs_out += 1
                ctr.bytes_out += len(data)
                self._maybe_signal_backpressure(chan, writer)
                self.log.debug("[TCP] chan=%s overlay->local %dB", chan, len(data))
            except Exception as e:
                self.log.info("[TCP] chan=%s write error: %r", chan, e)
            return

        # CLOSE
        if mtype == ChannelMux.MType.CLOSE:
            tup = self._tcp_by_chan.pop(chan, None)
            if tup:
                _, writer = tup
                self._tcp_pending_data.pop(chan, None)
                self._tcp_by_writer.pop(writer, None)
                self._tcp_role_by_chan.pop(chan, None)
                self._chan_owner_peer_id.pop(chan, None)
                try:
                    writer.close()
                except Exception:
                    pass
            self._forget_tcp_open_key(chan)
            self.log.info("[TCP] chan=%s CLOSE => local teardown map_size=%s", chan, len(self._tcp_by_chan))

    # ---------- TCP backpressure ----------
    def _ensure_backpressure_task(self, chan: int, writer: asyncio.StreamWriter) -> None:
        if chan in self._tcp_backpressure_tasks:
            return
        evt = self._tcp_backpressure_evt.setdefault(chan, asyncio.Event())
        thr = int(getattr(self, "_tcp_drain_threshold", 1))
        latency_ms = int(getattr(self, "_tcp_bp_latency_ms", 300))
        poll_s = float(getattr(self, "_tcp_bp_poll_interval_s", 0.05))
        latency_ns = max(0, latency_ms) * 1_000_000

        async def _bp():
            try:
                nonzero_since_ns = 0
                while True:
                    # wait for size-based signal or poll
                    try:
                        await asyncio.wait_for(evt.wait(), timeout=poll_s)
                        evt.clear()
                    except asyncio.TimeoutError:
                        pass
                    transport = getattr(writer, "transport", None)
                    if not transport:
                        break
                    try:
                        wbs = transport.get_write_buffer_size()
                    except Exception:
                        wbs = 0
                    now_ns = time.monotonic_ns()
                    if wbs > 0:
                        if nonzero_since_ns == 0:
                            nonzero_since_ns = now_ns
                    else:
                        nonzero_since_ns = 0
                    do_drain = False
                    reason = ""
                    if wbs >= thr:
                        do_drain = True
                        reason = f"wbuf={wbs} thr={thr}"
                    elif latency_ns > 0 and nonzero_since_ns and (now_ns - nonzero_since_ns) >= latency_ns:
                        do_drain = True
                        waited_ms = (now_ns - nonzero_since_ns) / 1e6
                        reason = f"latency_ms={waited_ms:.1f} (>= {latency_ms})"
                    if do_drain:
                        try:
                            t0 = time.perf_counter()
                            await writer.drain()
                            dt = (time.perf_counter() - t0) * 1000.0
                            self.log.debug("[TCP/BP] chan=%s drain in %.2f ms; %s", chan, dt, reason)
                        except Exception as e:
                            self.log.info("[TCP/BP] chan=%s drain failed: %r", chan, e)
                            break
            except asyncio.CancelledError:
                return
            finally:
                self._tcp_backpressure_tasks.pop(chan, None)
                self._tcp_backpressure_evt.pop(chan, None)

        self._tcp_backpressure_tasks[chan] = self.loop.create_task(_bp())

    def _maybe_signal_backpressure(self, chan: int, writer: asyncio.StreamWriter) -> None:
        try:
            transport = writer.transport  # type: ignore[attr-defined]
            if not transport:
                return
            wbs = transport.get_write_buffer_size()
            thr = int(getattr(self, "_tcp_drain_threshold", 1))
            if wbs >= thr:
                evt = self._tcp_backpressure_evt.get(chan)
                if evt:
                    self.log.debug("[TCP/BP] chan=%s signal drain; wbuf=%s thr=%s", chan, wbs, thr)
                    evt.set()
        except Exception:
            pass
    # ---------- TCP endpoint helper ----------
    def _tcp_endpoints(self, writer: asyncio.StreamWriter) -> Tuple[Optional[Tuple[str, int]], Optional[Tuple[str, int]]]:
        """
        Return (local_endpoint, remote_endpoint) as (ip, port) tuples if available.
        Handles IPv6 tuples len>=2; returns None when not accessible.
        """
        try:
            transport = getattr(writer, "transport", None)  # type: ignore[attr-defined]
            if not transport:
                return None, None
            l = transport.get_extra_info("sockname")
            r = transport.get_extra_info("peername")
            def _ip_port(x):
                return (x[0], int(x[1])) if isinstance(x, tuple) and len(x) >= 2 else None
            return _ip_port(l), _ip_port(r)
        except Exception:
            return None, None
    # ---------- helpers ----------
    def _alloc_udp_id(self) -> int:
        start = self._chan_id_start if self._chan_id_stride == 2 else self.UDP_MIN_ID
        stride = self._chan_id_stride if self._chan_id_stride > 0 else 1
        cid = self._next_udp_id
        if cid > self.UDP_MAX_ID or cid < start:
            cid = start
        nxt = cid + stride
        self._next_udp_id = nxt if nxt <= self.UDP_MAX_ID else start
        return cid

    def _alloc_tcp_id(self) -> int:
        start = self._chan_id_start if self._chan_id_stride == 2 else self.TCP_MIN_ID
        stride = self._chan_id_stride if self._chan_id_stride > 0 else 1
        cid = self._next_tcp_id
        if cid > self.TCP_MAX_ID or cid < start:
            cid = start

        # Skip active channel ids during wrap-around to preserve unique in-flight identity.
        scan_start = cid
        while cid in self._tcp_by_chan:
            nxt = cid + stride
            cid = nxt if nxt <= self.TCP_MAX_ID else start
            if cid == scan_start:
                raise RuntimeError("no free TCP channel ids available")

        nxt = cid + stride
        self._next_tcp_id = nxt if nxt <= self.TCP_MAX_ID else start
        self.log.debug(
            "[TCP/SRV] alloc chan=%s next=%s active=%s",
            cid,
            self._next_tcp_id,
            len(self._tcp_by_chan),
        )
        return cid

    def _ctr(self, proto: ChannelMux.Proto, chan: int) -> _ChanCtr:
        key = (chan, proto)
        c = self._chan_stats.get((chan, proto))
        if c is None:
            c = _ChanCtr()
            self._chan_stats[(chan, proto)] = c
        return c

    # ---------- Logging helpers ----------

    def _log_app_msg(self, dir: str, data: bytes) -> None:
        # chan_id(2) | proto(1) | counter(2) | mtype(1) | data_len(2)
        parsed = self._unpack_mux(data)
        if not parsed:
            self.log.warning(f"[APP] {dir} not parsed len={len(data)}: {data[:16].hex().upper()}")
            return
        chan_id, proto, counter, mtype, payload_mv = parsed
        data = bytes(payload_mv)
        src="[APP]"

        if len(data) > 65535:
            self.log.error(
                f"{src} Application message longer than 65535 bytes; makes trouble!"
            )

        protostr = ''
        if proto == ChannelMux.Proto.UDP:
            protostr = "UDP"
        if proto == ChannelMux.Proto.TCP:
            protostr = "TCP"

        basestr=f"{src} {protostr}:{chan_id} {dir} CNT:{counter}"

        if mtype == ChannelMux.MType.OPEN:
            try:
                pay = self._dbg_parse_open_v4(data) 
            except Exception:
                pay = ''
            self.log.info(f"{basestr} OPEN {pay}")
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2:
            decoded = self._decode_remote_services_set_v2(data)
            if decoded is None:
                self.log.info(f"{basestr} REMOTE_SERVICES_SET_V2 invalid len={len(data)}")
            else:
                iid, seq, services = decoded
                self.log.info(
                    "%s REMOTE_SERVICES_SET_V2 iid=%s seq=%s count=%s",
                    basestr,
                    iid,
                    seq,
                    len(services),
                )
        if mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V1:
            self.log.info(f"{basestr} REMOTE_SERVICES_SET_V1 len={len(data)} (legacy/unsupported)")
        if mtype == ChannelMux.MType.DATA:
            self.log.debug(f"{basestr} DATA len={len(data)}:  {data[:5].hex().upper()}")
        if mtype == ChannelMux.MType.CLOSE:
            self.log.info(f"{basestr} CLOSE")

    def _dbg_parse_open_v4(self, payload: bytes) -> str:
        try:
            if len(payload) < 22 or payload[:2] != b"O4":
                return ""
            instance_id, connection_seq, svc_id, l_proto, l_len = struct.unpack(">QIHBB", payload[2:18])
            off = 18
            if len(payload) < off + l_len + 3:
                return ""
            l_bind = payload[off:off+l_len].decode("utf-8", "ignore")
            off += l_len
            l_port, r_proto = struct.unpack(">HB", payload[off:off+3])
            off += 3
            (hlen,) = struct.unpack(">B", payload[off:off+1])
            off += 1
            if len(payload) < off + hlen + 2:
                return ""
            host = payload[off:off+hlen].decode("utf-8", "ignore")
            off += hlen
            (r_port,) = struct.unpack(">H", payload[off:off+2])
            proto_s = "TCP" if r_proto == 1 else "UDP"
            l_proto_s = "TCP" if l_proto == 1 else "UDP"
            return (
                f"OPENv4 iid={instance_id} seq={connection_seq} svc={svc_id} "
                f"l={l_proto_s} {l_bind}:{l_port} r={proto_s} {host}:{r_port}"
            )
        except Exception:
            return ""

    # --- in ChannelMux, replace the old helper with this version ---
    def _log_conn(
        self,
        dir: str,            # "<-" or "->"
        mtype: str,          # "UDP" / "UDP*:" etc.
        chan_id: int,
        data: bytes,
        src: Optional[Tuple[str, int]] = None,
        dst: Optional[Tuple[str, int]] = None
    ) -> None:
        if not self.session.is_connected():
            return
        if len(data) > 65535:
            self.log.error("[NET] Too long for UDP frame; will be dropped downstream")
            return

        # Build "a.b.c.d:p -> e.f.g.h:q" if available; preserve old format otherwise
        path = ""
        try:
            if src and dst:
                path = f"  {src[0]}:{src[1]} -> {dst[0]}:{dst[1]}"
        except Exception:
            path = ""

        # Keep the short preview you already had
        self.log.debug(
            f"[NET] {mtype}:{chan_id} {dir}{path}  "
            f"len={len(data)}:  {data[:5].hex().upper()}"
        )

    # --- Dashboard helpers ---

    def _svc_spec_or_none(self, svc_id: int):
        try:
            i = int(svc_id)
            local = self._local_services.get(("local", 0, i))
            if local is not None:
                return local
            for key, spec in self._peer_installed_services.items():
                if key[0] == "peer" and int(key[2]) == i:
                    return spec
            return None
        except Exception:
            return None

    def _chan_stat_dict(self, chan: int, proto: "ChannelMux.Proto") -> dict:
        c = self._chan_stats.get((chan, proto))
        if c is None:
            return {
                "rx_msgs": 0,
                "tx_msgs": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
        return {
            "rx_msgs": int(getattr(c, "msgs_in", 0)),
            "tx_msgs": int(getattr(c, "msgs_out", 0)),
            "rx_bytes": int(getattr(c, "bytes_in", 0)),
            "tx_bytes": int(getattr(c, "bytes_out", 0)),
        }

    def snapshot_udp_connections(self) -> list[dict]:
        rows: list[dict] = []

        # Server-side UDP mappings: local client addr -> local listening port -> configured remote destination
        for chan, tup in list(self._udp_by_chan.items()):
            try:
                svc_key, src_addr = tup
            except Exception:
                continue

            svc_id = int(svc_key[2])
            spec = self._svc_spec_or_none(svc_id)
            srv_tr = self._svc_udp_servers.get(svc_key)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None

            src_ep = (src_addr[0], int(src_addr[1])) if isinstance(src_addr, tuple) and len(src_addr) >= 2 else None
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "source": src_ep,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": stats,
            })

        # UDP listeners: bound sockets waiting for first client/channel mapping.
        for svc_key, srv_tr in list(self._svc_udp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                "svc_id": svc_id,
                "source": None,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": {
                    "rx_msgs": 0,
                    "tx_msgs": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                },
            })

        # Client-side UDP transports: locally created connected UDP socket to remote destination
        for chan, tr in list(self._udp_client_transports.items()):
            try:
                sockname = tr.get_extra_info("sockname")
                peername = tr.get_extra_info("peername")
                local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
                peer_ep = (peername[0], int(peername[1])) if isinstance(peername, tuple) and len(peername) >= 2 else None
                svc_id = self._udp_client_svc_id.get(chan)
                spec = self._svc_spec_or_none(svc_id) if svc_id is not None else None
                stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

                rows.append({
                    "protocol": "udp",
                    "role": "client",
                    "state": "connected",
                    "chan_id": int(chan),
                    "svc_id": int(svc_id) if svc_id is not None else None,
                    "source": local_ep,
                    "local": local_ep,
                    "local_port": int(local_ep[1]) if local_ep else None,
                    "remote_destination": (
                        {"host": peer_ep[0], "port": int(peer_ep[1])} if peer_ep else
                        ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                    ),
                    "stats": stats,
                })
            except Exception:
                continue

        rows.sort(
            key=lambda x: (
                x["protocol"],
                x["role"],
                str(x.get("state") or ""),
                -1 if x["chan_id"] is None else int(x["chan_id"]),
            )
        )
        return rows

    def snapshot_tcp_connections(self) -> list[dict]:
        rows: list[dict] = []

        for chan, tup in list(self._tcp_by_chan.items()):
            try:
                svc_id, writer = tup
            except Exception:
                continue

            spec = self._svc_spec_or_none(svc_id)
            role = self._tcp_role_by_chan.get(chan, "unknown")
            local_ep, remote_ep = self._tcp_endpoints(writer)
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.TCP)

            if role == "server":
                source = remote_ep
                local = local_ep
                remote_destination = (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                )
            else:
                source = local_ep
                local = local_ep
                remote_destination = (
                    {"host": remote_ep[0], "port": int(remote_ep[1])} if remote_ep else
                    ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                )

            rows.append({
                "protocol": "tcp",
                "role": role,
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "source": source,
                "local": local,
                "local_port": int(local[1]) if local else (int(spec.l_port) if spec else None),
                "remote_destination": remote_destination,
                "stats": stats,
            })

        rows.sort(key=lambda x: (x["protocol"], x["role"], x["chan_id"]))
        return rows

    def snapshot_connections(self) -> dict:
        udp_rows = self.snapshot_udp_connections()
        tcp_rows = self.snapshot_tcp_connections()
        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "counts": {
                "udp": len(udp_rows),
                "tcp": len(tcp_rows),
            },
        }        
    
    def _svc_spec_or_none(self, svc_id: int):
        try:
            i = int(svc_id)
            local = self._local_services.get(("local", 0, i))
            if local is not None:
                return local
            for key, spec in self._peer_installed_services.items():
                if key[0] == "peer" and int(key[2]) == i:
                    return spec
            return None
        except Exception:
            return None

    def _chan_stat_dict(self, chan: int, proto: "ChannelMux.Proto") -> dict:
        c = self._chan_stats.get((chan, proto))
        if c is None:
            return {
                "rx_msgs": 0,
                "tx_msgs": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
        return {
            "rx_msgs": int(getattr(c, "msgs_in", 0)),
            "tx_msgs": int(getattr(c, "msgs_out", 0)),
            "rx_bytes": int(getattr(c, "bytes_in", 0)),
            "tx_bytes": int(getattr(c, "bytes_out", 0)),
        }

    def snapshot_udp_connections(self) -> list[dict]:
        rows: list[dict] = []

        # Server-side UDP mappings: local client addr -> local listening port -> configured remote destination
        for chan, tup in list(self._udp_by_chan.items()):
            try:
                svc_key, src_addr = tup
            except Exception:
                continue

            svc_id = int(svc_key[2])
            spec = self._svc_spec_or_none(svc_id)
            srv_tr = self._svc_udp_servers.get(svc_key)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None

            src_ep = (src_addr[0], int(src_addr[1])) if isinstance(src_addr, tuple) and len(src_addr) >= 2 else None
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "source": src_ep,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": stats,
            })

        # UDP listeners: bound sockets waiting for first client/channel mapping.
        for svc_key, srv_tr in list(self._svc_udp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            sockname = srv_tr.get_extra_info("sockname") if srv_tr else None
            local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
            rows.append({
                "protocol": "udp",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                "svc_id": svc_id,
                "source": None,
                "local": local_ep,
                "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                "remote_destination": (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                ),
                "stats": {
                    "rx_msgs": 0,
                    "tx_msgs": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                },
            })

        # Client-side UDP transports: locally created connected UDP socket to remote destination
        for chan, tr in list(self._udp_client_transports.items()):
            try:
                sockname = tr.get_extra_info("sockname")
                peername = tr.get_extra_info("peername")
                local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
                peer_ep = (peername[0], int(peername[1])) if isinstance(peername, tuple) and len(peername) >= 2 else None
                svc_id = self._udp_client_svc_id.get(chan)
                spec = self._svc_spec_or_none(svc_id) if svc_id is not None else None
                stats = self._chan_stat_dict(chan, ChannelMux.Proto.UDP)

                rows.append({
                    "protocol": "udp",
                    "role": "client",
                    "state": "connected",
                    "chan_id": int(chan),
                    "svc_id": int(svc_id) if svc_id is not None else None,
                    "source": local_ep,
                    "local": local_ep,
                    "local_port": int(local_ep[1]) if local_ep else None,
                    "remote_destination": (
                        {"host": peer_ep[0], "port": int(peer_ep[1])} if peer_ep else
                        ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                    ),
                    "stats": stats,
                })
            except Exception:
                continue

        rows.sort(
            key=lambda x: (
                x["protocol"],
                x["role"],
                str(x.get("state") or ""),
                -1 if x["chan_id"] is None else int(x["chan_id"]),
            )
        )
        return rows

    def snapshot_tcp_connections(self) -> list[dict]:
        rows: list[dict] = []

        for chan, tup in list(self._tcp_by_chan.items()):
            try:
                svc_id, writer = tup
            except Exception:
                continue

            spec = self._svc_spec_or_none(svc_id)
            role = self._tcp_role_by_chan.get(chan, "unknown")
            local_ep, remote_ep = self._tcp_endpoints(writer)
            stats = self._chan_stat_dict(chan, ChannelMux.Proto.TCP)

            if role == "server":
                source = remote_ep
                local = local_ep
                remote_destination = (
                    {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                )
            else:
                source = local_ep
                local = local_ep
                remote_destination = (
                    {"host": remote_ep[0], "port": int(remote_ep[1])} if remote_ep else
                    ({"host": spec.r_host, "port": int(spec.r_port)} if spec else None)
                )

            rows.append({
                "protocol": "tcp",
                "role": role,
                "state": "connected",
                "chan_id": int(chan),
                "svc_id": int(svc_id),
                "source": source,
                "local": local,
                "local_port": int(local[1]) if local else (int(spec.l_port) if spec else None),
                "remote_destination": remote_destination,
                "stats": stats,
            })

        # TCP listeners: bound server sockets waiting for incoming channels.
        for svc_key, srv in list(self._svc_tcp_servers.items()):
            try:
                svc_id = int(svc_key[2])
            except Exception:
                continue
            spec = self._svc_spec_or_none(svc_id)
            sockets = list((getattr(srv, "sockets", None) or []))
            if not sockets:
                sockets = [None]
            for sock in sockets:
                try:
                    sockname = sock.getsockname() if sock is not None else None
                except Exception:
                    sockname = None
                local_ep = (sockname[0], int(sockname[1])) if isinstance(sockname, tuple) and len(sockname) >= 2 else None
                rows.append({
                    "protocol": "tcp",
                    "role": "server",
                    "state": "listening",
                    "chan_id": None,
                    "svc_owner_peer_id": int(svc_key[1]) if len(svc_key) >= 2 and str(svc_key[0]) == "peer" else None,
                    "svc_id": svc_id,
                    "source": None,
                    "local": local_ep,
                    "local_port": int(local_ep[1]) if local_ep else (int(spec.l_port) if spec else None),
                    "remote_destination": (
                        {"host": spec.r_host, "port": int(spec.r_port)} if spec else None
                    ),
                    "stats": {
                        "rx_msgs": 0,
                        "tx_msgs": 0,
                        "rx_bytes": 0,
                        "tx_bytes": 0,
                    },
                })

        rows.sort(
            key=lambda x: (
                x["protocol"],
                x["role"],
                str(x.get("state") or ""),
                -1 if x["chan_id"] is None else int(x["chan_id"]),
            )
        )
        return rows

    def snapshot_connections(self) -> dict:
        udp_rows = self.snapshot_udp_connections()
        tcp_rows = self.snapshot_tcp_connections()
        udp_listening = sum(1 for row in udp_rows if str(row.get("state", "connected")).lower() == "listening")
        tcp_listening = sum(1 for row in tcp_rows if str(row.get("state", "connected")).lower() == "listening")
        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "counts": {
                "udp": len(udp_rows) - udp_listening,
                "tcp": len(tcp_rows) - tcp_listening,
                "udp_listening": udp_listening,
                "tcp_listening": tcp_listening,
            },
        }

# ============================================================================
STATE_DISCONNECTED = "DISCONNECTED"
STATE_CONNECTED = "CONNECTED"

class StatsBoard:
    """
    Dashboard + statistics aggregator.

    Responsibilities:
      - Encapsulate UI flags via register_cli()
      - Track byte counters and state
      - Render dashboard / line output periodically (status task)
      - Consume events from Runner (on_* methods)
      - Read RTT/inflight from a Session reference
    """

    # ---- CLI integration -------------------------------------------------------
    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        """
        Register only the UI-related flags so other classes remain unaware.
        Mirrors previous defaults/behavior.
        """
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False

        if not _has('--status'):
            # Keep previous behavior: status enabled by default.
            p.add_argument('--status', action='store_true', default=True,
                           help='enable periodic status (default: on)')
        if not _has('--no-dashboard'):
            p.add_argument('--no-dashboard', action='store_true',
                           help='disable non-scrolling dashboard (print multiline blocks instead)')

    # ---- lifecycle & state -----------------------------------------------------
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log = logging.getLogger("stats_board")
        DebugLoggingConfigurator.debug_logger_status(self.log)

        # References provided by Runner
        self.session: Optional[Session] = None     # for RTT/inflight/ACK counters
        self.mux: Optional["ChannelMux"] = None         # for open connection counts
        self.peer_proto: Optional[PeerProtocol] = None  # for decode error counters (optional)

        # Task control
        self._stop_evt = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

        # Throughput totals
        self.app_rx_total = 0  # local->peer (overlay direction)
        self.app_tx_total = 0  # peer->local (local sockets direction)
        self.peer_rx_total = 0
        self.peer_tx_total = 0

        self._last_app_rx_rate_kbps = 0.0
        self._last_app_tx_rate_kbps = 0.0
        self._last_peer_rx_rate_kbps = 0.0
        self._last_peer_tx_rate_kbps = 0.0

        # Rate snapshot
        self._last_meter_ts = time.time()
        self._last_app_rx = 0
        self._last_app_tx = 0
        self._last_peer_rx = 0
        self._last_peer_tx = 0

        # UI cosmetics
        self._dashboard_enabled = not args.no_dashboard
        self._overlay_peer_str = "n/a"
        first_transport = str(getattr(args, "overlay_transport", "myudp") or "myudp").split(",", 1)[0].strip().lower()
        self._has_fixed_overlay_peer = _has_configured_overlay_peer(args, first_transport)
        bind_attr, _, _, listen_port_attr = _overlay_cli_attrs(first_transport)
        bind_val = getattr(args, bind_attr, "::")
        default_listen_port = {"myudp": 4433, "tcp": 8081, "quic": 443, "ws": 8080}.get(first_transport, 4433)
        listen_port = int(getattr(args, listen_port_attr, default_listen_port))
        self._overlay_bind_str = f"{bind_val}:{listen_port}"
        if self._has_fixed_overlay_peer:
            self._overlay_peer_str = "—"
        self._local_side_str = self._summarize_local_sides(args)

        # Connection state
        self._conn_state = STATE_DISCONNECTED
        self._last_rtt_ok_ns: int = 0

        self.session_is_connected = lambda: False
        self.session_get_metrics  = lambda: SessionMetrics()

    # ---- wiring from Runner ----------------------------------------------------
    def set_session_ref(self, s: Optional[Session]) -> None:
        self.session = s

    def set_mux_ref(self, m: Optional["ChannelMux"]) -> None:
        self.mux = m

    def set_peer_proto(self, pp: Optional[PeerProtocol]) -> None:
        self.peer_proto = pp

    # ---- event sinks (Runner calls these) -------------------------------------
    def on_peer_set(self, host: str, port: int) -> None:
        if not self._has_fixed_overlay_peer:
            self._overlay_peer_str = "n/a"
            return
        self._overlay_peer_str = f"[{host}]:{port}" if ':' in host and not host.startswith('[') else f"{host}:{port}"
        self.log.debug(f"on_peer_set({host} {port} )")

    def on_state_change(self, connected: bool) -> None:
        self.log.debug(f"on_state_change({self._conn_state} -> {connected})")
        self._conn_state = STATE_CONNECTED if connected else STATE_DISCONNECTED

    def on_rtt_success(self, echo_tx_ns: int) -> None:
        self._last_rtt_ok_ns = now_ns()
        self.log.debug(f"on_rtt_success({echo_tx_ns})")

    def on_peer_rx_bytes(self, n: int) -> None:
        self.peer_rx_total += n
        self.log.debug(f"on_peer_rx_bytes(+{int(n)})")

    def on_peer_tx_bytes(self, n: int) -> None:
        self.peer_tx_total += n
        self.log.debug(f"on_peer_tx_bytes(+{int(n)})")

    def on_app_rx_bytes(self, n: int) -> None:
        self.app_rx_total += n
        self.log.debug(f"on_app_rx_bytes(+{int(n)})")

    def on_app_tx_bytes(self, n: int) -> None:        
        self.app_tx_total += n
        self.log.debug(f"on_app_tx_bytes(+{int(n)})")


    def bind_session(self, session: ISession):
        self.session_is_connected = session.is_connected
        self.session_get_metrics  = session.get_metrics


    # ---- lifecycle (status task) ----------------------------------------------
    async def start(self) -> None:
        if not getattr(self.args, "status", True):
            return
        if self._dashboard_enabled:
            sys.stdout.write(ANSI_HIDE_CURSOR)
            sys.stdout.flush()
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._status_task_fn())

    async def stop(self) -> None:
        self._stop_evt.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass
        if self._dashboard_enabled:
            sys.stdout.write(ANSI_SHOW_CURSOR)
            sys.stdout.flush()

    # ---- helpers moved from Runner (unchanged strings) ------------------------
    def _summarize_local_sides(self, a: argparse.Namespace) -> str:
#        if a.udp_role == 'server':
#            udp = f"UDP srv {a.udp_listen_bind}:{a.udp_own_port}"
#        else:
#            udp = f"UDP cli -> {a.udp_target_host}:{a.udp_target_port} (bind {a.udp_bind}:ephem)"
#        if a.tcp_role == 'server':
#            tcp = f"TCP srv {a.tcp_listen_bind}:{a.tcp_own_port}"
#        else:
#            tcp = f"TCP cli -> {a.tcp_target_host}:{a.tcp_target_port} (bind {a.tcp_bind}:ephem)"
#        return f"{udp}\n {tcp}"
        return f""

    def _render_retx_stats(self) -> str:
        s = self.session
        if not s:
            return ""
        h = s.stats_hist
        confirmed = max(1, int(h.get('confirmed_total', 0)))
        def pct(n): return (100.0 * float(h.get(n, 0))) / confirmed
        return (
            "Retransmit distribution (confirmed app DATA only)\n"
            f" once : {h.get('once', 0):6d} ({pct('once'):5.1f}%)\n"
            f" twice : {h.get('twice', 0):6d} ({pct('twice'):5.1f}%)\n"
            f" thrice : {h.get('thrice', 0):6d} ({pct('thrice'):5.1f}%)\n"
            f" > three: {h.get('gt3', 0):6d} ({pct('gt3'):5.1f}%)\n"
            f" confirmed / created : {h.get('confirmed_total', 0)} / {h.get('created_total', 0)}"
        )

    def _render_error_counters(self) -> str:
        unknown = 0
        pp = self.peer_proto
        if pp is not None and hasattr(pp, "unidentified_frames"):
            try:
                unknown = int(getattr(pp, "unidentified_frames", 0))
            except Exception:
                pass
        return (
            "----------------------------------------------------------------\n"
            f"Decode errors: Unidentified frames={unknown}\n"
        )

    def _render_status_block(
        self,
        dt: float,
        app_rx_r: float,
        app_tx_r: float,
        peer_rx_r: float,
        peer_tx_r: float,
        *,
        compact: bool,
    ) -> str:
        """
        Unified renderer for both dashboard and line-by-line modes.
        If compact=True -> minimal header/title and no ANSI/non-scrolling tips.
        If compact=False -> full dashboard title and footer.
        """
        s = self.session
        kb_tot = 1024.0
        now_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        m = self.session_get_metrics()
        last_ok = (
            ((self.session.last_rtt_ok_ns if self.session else 0) or 0)
            or (m.last_rtt_ok_ns or 0)
            or self._last_rtt_ok_ns
        )
        age_str = f"{max(0.0, (now_ns() - last_ok)/1e9):0.1f}s ago" if last_ok else "—"

        udp_count = self.mux.udp_open_count() if self.mux else 0
        tcp_count = self.mux.tcp_open_count() if self.mux else 0

        def _fmt(v, nd=None):
            if v is None:
                return "n/a"
            if isinstance(v, float) and nd is not None:
                return f"{v:.{nd}f}"
            return str(v)

        title = (
            "UDP/TCP Multiplexed Transfer — DASHBOARD (non-scrolling)\n"
            "----------------------------------------------------------------\n"
            if not compact else
            "=== STATUS =======================================================\n"
        )

        header = (
            f"Updated: {now_s} (Δ~{dt:.1f}s) "
            f"Peer State: {self._conn_state} "
            f"Last RTT OK: {age_str}\n"
            f"Overlay bind : {self._overlay_bind_str}\n"
            f"Overlay peer : {self._overlay_peer_str}\n"
            f"Local I/F : {self._local_side_str}\n"
            f"Open Conns : UDP={udp_count} TCP={tcp_count}\n"
        )

        # RTT + flow (transport-agnostic: values may be 'n/a' on TCP)
        rtt_and_flow = (
            f"RTT(ms): "
            f"cur={_fmt(m.rtt_sample_ms, 1)} "
            f"est={_fmt(m.rtt_est_ms, 1)} "
        )
        if s:
           rtt_and_flow += ( 
                f"inflight={_fmt(m.inflight)}/{_fmt(m.max_inflight)} "
                f"waiting={_fmt(m.waiting_count)}\n"
                f"ACKed={_fmt(m.last_ack_peer)} "
                f"sent_ctr={_fmt(m.last_sent_ctr)} "
                f"expected={_fmt(m.expected)} "
                f"peer_missed={_fmt(m.peer_missed_count)} "
                f"our_missed={_fmt(m.our_missed_count)}"
           )
        rtt_and_flow += ( f"\n" )
    
        meters = (
            "----------------------------------------------------------------\n"
            f"App I/F : RX={app_rx_r:7.1f} kB/s TX={app_tx_r:7.1f} kB/s "
            f"(tot RX={self.app_rx_total/kb_tot:,.0f} kB, TX={self.app_tx_total/kb_tot:,.0f} kB)\n"
            f"Peer I/F: RX={peer_rx_r:7.1f} kB/s TX={peer_tx_r:7.1f} kB/s "
            f"(tot RX={self.peer_rx_total/kb_tot:,.0f} kB, TX={self.peer_tx_total/kb_tot:,.0f} kB)\n"
        )

        errors = self._render_error_counters()
        retx = "----------------------------------------------------------------\n" + self._render_retx_stats() + "\n"

        footer = (
            "----------------------------------------------------------------\n"
            "Press Ctrl+C to exit. Use --no-dashboard to switch to line-by-line output.\n"
            if not compact else
            "=================================================================\n"
        )

        return (title + header + rtt_and_flow + meters + errors + retx + footer)

    def _render_dashboard(
        self,
        dt: float,
        app_rx_r: float,
        app_tx_r: float,
        peer_rx_r: float,
        peer_tx_r: float
    ) -> str:
        # Keep existing call sites: delegate to unified renderer
        return self._render_status_block(
            dt, app_rx_r, app_tx_r, peer_rx_r, peer_tx_r, compact=False
        )

    async def _status_task_fn(self) -> None:
        try:
            while not self._stop_evt.is_set():
                await asyncio.sleep(1.0)
                now_t = time.time()
                dt = max(1e-6, now_t - self._last_meter_ts)
                da_rx = self.app_rx_total - self._last_app_rx
                da_tx = self.app_tx_total - self._last_app_tx
                dp_rx = self.peer_rx_total - self._last_peer_rx
                dp_tx = self.peer_tx_total - self._last_peer_tx
                kb = 1024.0
                app_rx_r = da_rx / kb / dt
                app_tx_r = da_tx / kb / dt
                peer_rx_r = dp_rx / kb / dt
                peer_tx_r = dp_tx / kb / dt
                self._last_meter_ts = now_t
                self._last_app_rx = self.app_rx_total
                self._last_app_tx = self.app_tx_total
                self._last_peer_rx = self.peer_rx_total
                self._last_peer_tx = self.peer_tx_total

                self._last_app_rx_rate_kbps = app_rx_r
                self._last_app_tx_rate_kbps = app_tx_r
                self._last_peer_rx_rate_kbps = peer_rx_r
                self._last_peer_tx_rate_kbps = peer_tx_r

                self._conn_state = STATE_CONNECTED if self.session_is_connected() else STATE_DISCONNECTED

                if self._dashboard_enabled:
                    sys.stdout.write(ANSI_HOME_CLEAR)
                    sys.stdout.write(self._render_dashboard(dt, app_rx_r, app_tx_r, peer_rx_r, peer_tx_r))
                    sys.stdout.flush()
                else:
                    # Reuse the unified renderer in compact mode (no ANSI, concise title/footer)
                    block = self._render_status_block(
                        dt, app_rx_r, app_tx_r, peer_rx_r, peer_tx_r, compact=True
                    )
                    print(block, flush=True)

        except asyncio.CancelledError:
            return
    def snapshot_status(self) -> dict:
        """
        Machine-readable snapshot of the same data shown in the text dashboard.
        Safe to call from the admin web handler.
        """
        kb_tot = 1024.0
        now_wall = time.time()
        now_ns_v = now_ns()

        m = self.session_get_metrics()

        last_ok = (
            ((self.session.last_rtt_ok_ns if self.session else 0) or 0)
            or (m.last_rtt_ok_ns or 0)
            or self._last_rtt_ok_ns
        )
        last_rtt_ok_age_sec = ((now_ns_v - last_ok) / 1e9) if last_ok else None

        udp_count = self.mux.udp_open_count() if self.mux else 0
        tcp_count = self.mux.tcp_open_count() if self.mux else 0

        def _num(v):
            return None if v is None else v

        hist = dict(getattr(self.session, "stats_hist", {}) or {})
        repeated_multiple = int(hist.get("thrice", 0)) + int(hist.get("gt3", 0))

        return {
            "updated_unix_ts": now_wall,
            "peer_state": self._conn_state,
            "overlay": {
                "bind": self._overlay_bind_str,
                "peer": self._overlay_peer_str,
                "local_side": self._local_side_str,
            },
            "open_connections": {
                "udp": int(udp_count),
                "tcp": int(tcp_count),
            },
            "traffic": {
                "app": {
                    "rx_total_bytes": int(self.app_rx_total),
                    "tx_total_bytes": int(self.app_tx_total),
                    "rx_total_kb": self.app_rx_total / kb_tot,
                    "tx_total_kb": self.app_tx_total / kb_tot,
                },
                "peer": {
                    "rx_total_bytes": int(self.peer_rx_total),
                    "tx_total_bytes": int(self.peer_tx_total),
                    "rx_total_kb": self.peer_rx_total / kb_tot,
                    "tx_total_kb": self.peer_tx_total / kb_tot,
                },
                "rates_kBps": {
                    "app_rx": self._last_app_rx_rate_kbps,
                    "app_tx": self._last_app_tx_rate_kbps,
                    "peer_rx": self._last_peer_rx_rate_kbps,
                    "peer_tx": self._last_peer_tx_rate_kbps,
                },
            },
            "transport": {
                "last_rtt_ok_age_sec": last_rtt_ok_age_sec,
                "rtt_sample_ms": _num(m.rtt_sample_ms),
                "rtt_est_ms": _num(m.rtt_est_ms),
                "inflight": _num(m.inflight),
                "max_inflight": _num(m.max_inflight),
                "waiting_count": _num(m.waiting_count),
                "last_ack_peer": _num(m.last_ack_peer),
                "last_sent_ctr": _num(m.last_sent_ctr),
                "expected": _num(m.expected),
                "peer_missed_count": _num(m.peer_missed_count),
                "our_missed_count": _num(m.our_missed_count),
            },
            "decode_errors": {
                "unidentified_frames": int(
                    getattr(self.peer_proto, "unidentified_frames", 0) if self.peer_proto else 0
                ),
            },
            "myudp": {
                "retransmit": {
                    "created_total": int(hist.get("created_total", 0)),
                    "confirmed_total": int(hist.get("confirmed_total", 0)),
                    "first_pass": int(hist.get("once", 0)),
                    "repeated_once": int(hist.get("twice", 0)),
                    "repeated_multiple": repeated_multiple,
                    "repeated_three_times": int(hist.get("thrice", 0)),
                    "repeated_over_three_times": int(hist.get("gt3", 0)),
                },
            },
        }
        
        self.log.debug(
            "[STATS/SNAPSHOT] peer_state=%s overlay_peer=%s "
            "peer_rx=%d peer_tx=%d app_rx=%d app_tx=%d rtt_est_ms=%s",
            payload["peer_state"],
            payload["overlay"]["peer"],
            payload["traffic"]["peer"]["rx_total_bytes"],
            payload["traffic"]["peer"]["tx_total_bytes"],
            payload["traffic"]["app"]["rx_total_bytes"],
            payload["traffic"]["app"]["tx_total_bytes"],
            payload["transport"]["rtt_est_ms"],
        )

# ============================================================================
class RunnerMuxAggregate:
    def __init__(self, muxes: List["ChannelMux"]):
        self._muxes = list(muxes)

    def udp_open_count(self) -> int:
        return sum(m.udp_open_count() for m in self._muxes)

    def tcp_open_count(self) -> int:
        return sum(m.tcp_open_count() for m in self._muxes)

    def snapshot_connections(self) -> dict:
        udp_rows: list[dict] = []
        tcp_rows: list[dict] = []
        udp_listening = 0
        tcp_listening = 0
        for mux in self._muxes:
            snap = mux.snapshot_connections()
            udp_rows.extend(snap.get("udp", []))
            tcp_rows.extend(snap.get("tcp", []))
            counts = snap.get("counts", {}) or {}
            udp_listening += int(counts.get("udp_listening", 0) or 0)
            tcp_listening += int(counts.get("tcp_listening", 0) or 0)
        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "counts": {
                "udp": len(udp_rows) - udp_listening,
                "tcp": len(tcp_rows) - tcp_listening,
                "udp_listening": udp_listening,
                "tcp_listening": tcp_listening,
            },
        }


class Runner:
    """
    Thin orchestrator: wires ISession + ChannelMux + StatsBoard and manages lifecycle.
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log = logging.getLogger("runner")
        DebugLoggingConfigurator.debug_logger_status(self.log)
        self._stop: Optional[asyncio.Event] = None
        self._stop_requested = False
        self._session_obj: Optional[ISession] = None
        self.mux: Optional["ChannelMux"] = None
        self._sessions: List[ISession] = []
        self._muxes: List["ChannelMux"] = []
        self._session_labels: List[str] = []
        self.stats = StatsBoard(args )
        self.admin_web = None
        self._restart_requested: Optional[asyncio.Event] = None
        self._restart_requested_flag = False
        self._shutdown_exit_code: Optional[int] = None
        self._last_connected_monotonic: Optional[float] = None
        self._last_disconnected_monotonic: Optional[float] = None
        self._client_restart_watchdog_task: Optional[asyncio.Task] = None        

    def _ensure_runtime_events(self) -> None:
        if self._stop is None:
            self._stop = asyncio.Event()
        if self._stop_requested:
            self._stop.set()
        if self._restart_requested is None:
            self._restart_requested = asyncio.Event()
        if self._restart_requested_flag:
            self._restart_requested.set()

    async def start(self) -> None:

        
        self.log.debug("[SERVER] Runner start on session id=%x", id(self))
        self._ensure_runtime_events()

        loop = asyncio.get_running_loop()
        transport_sessions = Runner.build_sessions_from_overlay(self.args)
        self._sessions = []
        self._muxes = []
        self._session_labels = []
        for transport_name, session in transport_sessions:
            session.set_on_state_change(lambda connected, transport_name=transport_name, session=session: self._on_state_change(transport_name, session, connected))
            session.set_on_peer_rx(self.stats.on_peer_rx_bytes)
            session.set_on_peer_tx(self.stats.on_peer_tx_bytes)
            session.set_on_peer_set(self.stats.on_peer_set)
            mux = ChannelMux.from_args(
                session,
                loop,
                self.args,
                on_local_rx_bytes=self.stats.on_app_rx_bytes,
                on_local_tx_bytes=self.stats.on_app_tx_bytes
            )
            self._sessions.append(session)
            self._muxes.append(mux)
            self._session_labels.append(transport_name)
            session.set_on_transport_epoch_change(
                lambda epoch, transport_name=transport_name, session=session, mux=mux:
                    self._on_transport_epoch_change(transport_name, session, mux, epoch)
            )
            await session.start()
            await mux.start()

        self._session_obj = self._sessions[0] if self._sessions else None
        self.stats.bind_session(self._session_obj)
        if self._muxes:
            self.mux = RunnerMuxAggregate(self._muxes)
        else:
            self.mux = None

        
        # 4) Provide references to StatsBoard and start it
        # For UDP overlays we still expose the inner Session (to render retransmit histograms).
        # For TCP overlays this will be None and the board will omit that section.
        inner = None
        real = getattr(self._session_obj, "_real", self._session_obj)  # unwrap SessionDebugShim if present

        try:
            if isinstance(real, UdpSession):
                self.stats.set_peer_proto(real.peer_proto)
        except Exception:
            pass

        if isinstance(real, UdpSession):
            inner = real.inner_session
        self.stats.set_session_ref(inner)  # now the dashboard can show inflight/ACKed/etc.

        self.stats.set_mux_ref(self.mux)
        if self.args.status:
            await self.stats.start()

    # --- add this block near the end of start() ---
        if getattr(self.args, "admin_web", False):
            self.admin_web = AdminWebUI(self.args, self)
            await self.admin_web.start()

        self._last_connected_monotonic = time.monotonic() if self._session_obj and self._session_obj.is_connected() else None
        self._last_disconnected_monotonic = None if self._session_obj and self._session_obj.is_connected() else time.monotonic()

        self._client_restart_watchdog_task = asyncio.create_task(
            self._client_restart_watchdog()
        )

    async def run(self):
        self.log.debug("[SERVER] Run entered")
        await self.start()
        self.log.debug("[SERVER] Run after start")

        assert self._stop is not None
        assert self._restart_requested is not None
        stop_task = asyncio.create_task(self._stop.wait())
        restart_task = asyncio.create_task(self._restart_requested.wait())

        try:
            done, pending = await asyncio.wait(
                [stop_task, restart_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            self.log.debug("[SERVER] Run Terminating Event")

            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        finally:
            try:
                self.log.debug("[RUNNER] wait for stop with 2.0 timeout")
                await asyncio.wait_for(self.stop(), timeout=2.0)
            except Exception:
                self.log.debug("[RUNNER] stop timed out during restart")

        if self._restart_requested is not None and self._restart_requested.is_set():
            self.log.warning("[RUNNER] exiting rc=75")
            raise SystemExit(75)

        if self._shutdown_exit_code is not None:
            self.log.warning("[RUNNER] exiting rc=%d", self._shutdown_exit_code)
            raise SystemExit(self._shutdown_exit_code)

        self.log.debug("[RUNNER] Leaving stop")


    async def stop(self):
        self.log.debug("[SERVER] Stop entered")
        if self._client_restart_watchdog_task is not None:
            self._client_restart_watchdog_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._client_restart_watchdog_task
            self._client_restart_watchdog_task = None
        if self.admin_web is not None:
            await self.admin_web.stop()
            self.admin_web = None        
        self._stop.set()

        self.log.debug("[RUNNER] stop: entering stats.stop")
        try:
            await self.stats.stop()
        except Exception:
            pass

        self.log.debug("[RUNNER] stop: entering mux.stop")
        try:
            for mux in reversed(self._muxes):
                await mux.stop()
        except Exception:
            pass

        self.log.debug("[RUNNER] stop: entering _session_obj")
        try:
            for session in reversed(self._sessions):
                await session.stop()
        except Exception:
            pass
        self.log.debug("[RUNNER] stop leaving")


    # ---- overlay state propagation (unchanged behavior) -----------------------
    def _on_state_change(self, transport_name: str, session: ISession, connected: bool):
        self.log.debug(f"[SERVER] _on_state_change transport={transport_name} connected={connected}")

        now_mono = time.monotonic()
        aggregate_connected = any(s.is_connected() for s in self._sessions) if self._sessions else connected
        if aggregate_connected:
            self._last_connected_monotonic = now_mono
            self._last_disconnected_monotonic = None
        else:
            if self._last_disconnected_monotonic is None:
                self._last_disconnected_monotonic = now_mono        
        # Update board
        self.stats.on_state_change(aggregate_connected)
        # Inform mux
        mux = None
        try:
            idx = self._sessions.index(session)
            mux = self._muxes[idx]
        except Exception:
            mux = None
        if mux:
            try:
                asyncio.get_running_loop().create_task(mux.on_overlay_state(connected))
            except RuntimeError:
                pass
        # Keep old behavior: reset sender on disconnect
        s = self.stats.session
        if not aggregate_connected and s:
            try:
                s.reset_sender()
            except Exception:
                pass

    def _on_transport_epoch_change(self, transport_name: str, session: ISession, mux: "ChannelMux", epoch: int) -> None:
        self.log.info(
            "[SERVER] transport epoch changed transport=%s session=%x epoch=%d",
            transport_name,
            id(session),
            epoch,
        )
        try:
            asyncio.get_running_loop().create_task(mux.on_transport_epoch_change(epoch))
        except RuntimeError:
            pass

    def request_restart(self) -> None:
        self.log.debug("[SERVER] Runner restart requested")
        self._restart_requested_flag = True
        if self._restart_requested is not None:
            self._restart_requested.set()

    def get_status_snapshot(self) -> dict:
        return self.stats.snapshot_status()

    def get_connections_snapshot(self) -> dict:
        if not self._muxes:
            return {
                "udp": [],
                "tcp": [],
                "counts": {"udp": 0, "tcp": 0, "udp_listening": 0, "tcp_listening": 0},
            }

        udp_rows: list[dict] = []
        tcp_rows: list[dict] = []
        udp_listening = 0
        tcp_listening = 0

        for idx, mux in enumerate(self._muxes):
            snap = mux.snapshot_connections()
            mux_udp_rows = list(snap.get("udp", []))
            mux_tcp_rows = list(snap.get("tcp", []))

            chan_to_peer_id: dict[int, str] = {}
            owner_peer_to_label: dict[int, str] = {}
            with contextlib.suppress(Exception):
                session = self._sessions[idx] if idx < len(self._sessions) else None
                getter = getattr(session, "get_overlay_peers_snapshot", None) if session is not None else None
                overlay_rows = list(getter() or []) if callable(getter) else []
                for p in overlay_rows:
                    peer_label = f"{idx}:{p.get('peer_id', 0)}"
                    with contextlib.suppress(Exception):
                        owner_peer_to_label[int(p.get("peer_id", 0))] = peer_label
                    for chan in (p.get("mux_chans") or []):
                        with contextlib.suppress(Exception):
                            chan_to_peer_id[int(chan)] = peer_label

            for row in mux_udp_rows:
                r = dict(row)
                chan = r.get("chan_id")
                if chan is not None:
                    r["peer_id"] = chan_to_peer_id.get(int(chan), str(idx))
                else:
                    owner_peer_id = r.get("svc_owner_peer_id")
                    if owner_peer_id is None:
                        # Locally owned listening services are still tied to this
                        # mux/peer slot; once traffic arrives the resulting channel
                        # will use the same slot-derived peer label fallback.
                        r["peer_id"] = str(idx)
                    else:
                        with contextlib.suppress(Exception):
                            owner_peer_id = int(owner_peer_id)
                        r["peer_id"] = owner_peer_to_label.get(owner_peer_id, f"{idx}:{owner_peer_id}")
                udp_rows.append(r)

            for row in mux_tcp_rows:
                r = dict(row)
                chan = r.get("chan_id")
                if chan is not None:
                    r["peer_id"] = chan_to_peer_id.get(int(chan), str(idx))
                else:
                    owner_peer_id = r.get("svc_owner_peer_id")
                    if owner_peer_id is None:
                        # Locally owned listening services are still tied to this
                        # mux/peer slot; once traffic arrives the resulting channel
                        # will use the same slot-derived peer label fallback.
                        r["peer_id"] = str(idx)
                    else:
                        with contextlib.suppress(Exception):
                            owner_peer_id = int(owner_peer_id)
                        r["peer_id"] = owner_peer_to_label.get(owner_peer_id, f"{idx}:{owner_peer_id}")
                tcp_rows.append(r)

            counts = snap.get("counts", {}) or {}
            udp_listening += int(counts.get("udp_listening", 0) or 0)
            tcp_listening += int(counts.get("tcp_listening", 0) or 0)

        return {
            "udp": udp_rows,
            "tcp": tcp_rows,
            "counts": {
                "udp": len(udp_rows) - udp_listening,
                "tcp": len(tcp_rows) - tcp_listening,
                "udp_listening": udp_listening,
                "tcp_listening": tcp_listening,
            },
        }

    def get_config_snapshot(self, include_secrets: bool = False) -> dict:
        blocked = {
            "config", "dump_config", "save_config", "save_format", "force",
            "help",
        }
        secret_keys = AdminWebUI._secret_config_keys()
        data = {}
        for k, v in vars(self.args).items():
            if k.startswith("_") or k in blocked:
                continue
            if k in secret_keys and not include_secrets:
                data[k] = ""
                continue
            if isinstance(v, (str, int, float, bool, list, dict)) or v is None:
                data[k] = v
            else:
                data[k] = str(v)
        return data

    def get_config_schema_snapshot(self) -> dict:
        sections = {k: set(v) for k, v in (getattr(self.args, "_config_sections", {}) or {}).items()}
        defaults = getattr(self.args, "_config_defaults", {}) or {}
        descriptions = getattr(self.args, "_config_help", {}) or {}
        choices = getattr(self.args, "_config_choices", {}) or {}

        # Keep transport endpoint knobs grouped with their transport sessions in the
        # admin UI, even when those options were originally registered elsewhere.
        transport_key_targets = {
            "udp_bind": "udp_session",
            "udp_own_port": "udp_session",
            "udp_peer": "udp_session",
            "udp_peer_port": "udp_session",
            "tcp_bind": "tcp_session",
            "tcp_own_port": "tcp_session",
            "tcp_peer": "tcp_session",
            "tcp_peer_port": "tcp_session",
            "quic_bind": "quic_session",
            "quic_own_port": "quic_session",
            "quic_peer": "quic_session",
            "quic_peer_port": "quic_session",
            "ws_bind": "ws_session",
            "ws_own_port": "ws_session",
            "ws_peer": "ws_session",
            "ws_peer_port": "ws_session",
        }
        for key, target_section in transport_key_targets.items():
            if not hasattr(self.args, key):
                continue
            for section_keys in sections.values():
                section_keys.discard(key)
            sections.setdefault(target_section, set()).add(key)

        schema: dict = {}
        for section in sorted(sections.keys()):
            section_keys = set(sections.get(section, []))
            section_log_key = f"log_{section}"
            if hasattr(self.args, section_log_key):
                section_keys.add(section_log_key)
            items = []
            for key in sorted(section_keys):
                if not hasattr(self.args, key):
                    continue
                row = {
                    "key": key,
                    "description": descriptions.get(key, "(no description)"),
                    "default": defaults.get(key, None),
                }
                if key in AdminWebUI._secret_config_keys():
                    row["secret"] = True
                if key in choices:
                    row["choices"] = list(choices.get(key, []))
                items.append(row)
            if items:
                schema[section] = items
        return schema

    def get_debug_logs(self, limit: int = 400) -> list:
        lim = max(1, min(int(limit), 1000))
        if not DEBUG_LOG_RING:
            return []
        return list(DEBUG_LOG_RING)[-lim:]

    def _session_metrics_snapshot(self, session_obj, fallback: Optional[SessionMetrics] = None) -> SessionMetrics:
        if session_obj is None:
            return fallback or SessionMetrics()
        getter = getattr(session_obj, "get_metrics", None)
        if callable(getter):
            with contextlib.suppress(Exception):
                return getter()
        try:
            return SessionMetrics(
                rtt_sample_ms=getattr(session_obj, "rtt_sample_ms", None),
                rtt_est_ms=getattr(session_obj, "rtt_est_ms", None),
                last_rtt_ok_ns=getattr(session_obj, "last_rtt_ok_ns", None),
                inflight=int(session_obj.in_flight()) if hasattr(session_obj, "in_flight") else None,
                max_inflight=getattr(session_obj, "max_in_flight", None),
                waiting_count=int(session_obj.waiting_count()) if hasattr(session_obj, "waiting_count") else None,
                last_ack_peer=getattr(session_obj, "last_ack_peer", None),
                last_sent_ctr=getattr(session_obj, "last_sent_ctr", None),
                expected=getattr(session_obj, "expected", None),
                peer_missed_count=getattr(session_obj, "peer_missed_count", None),
                our_missed_count=len(getattr(session_obj, "missing", [])) if hasattr(session_obj, "missing") else None,
            )
        except Exception:
            return fallback or SessionMetrics()

    def _session_retransmit_stats(self, session_obj) -> dict:
        hist: dict = {}
        buffered_frames = None
        with contextlib.suppress(Exception):
            inner = getattr(session_obj, "inner_session", session_obj)
            hist = dict(getattr(inner, "stats_hist", {}) or {})
            waiting_count = getattr(inner, "waiting_count", None)
            if callable(waiting_count):
                buffered_frames = int(waiting_count())
        return {
            "buffered_frames": buffered_frames,
            "first_pass": int(hist.get("once", 0)),
            "repeated_once": int(hist.get("twice", 0)),
            "repeated_multiple": int(hist.get("thrice", 0)) + int(hist.get("gt3", 0)),
            "confirmed_total": int(hist.get("confirmed_total", 0)),
        }

    def _overlay_listen_label(self, transport: str, session: ISession) -> Optional[str]:
        t = str(transport or "myudp").strip().lower()
        bind_attr, _, _, listen_port_attr = _overlay_cli_attrs(t)
        source_args = getattr(session, "_args", None) or self.args
        bind_host = str(getattr(source_args, bind_attr, "") or "")
        raw_port = getattr(source_args, listen_port_attr, None)
        if raw_port is None:
            return None
        with contextlib.suppress(Exception):
            listen_port = int(raw_port)
            if listen_port <= 0:
                return None
            host = bind_host or "0.0.0.0"
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            return f"{host}:{listen_port}"
        return None

    def get_peer_connections_snapshot(self) -> dict:
        peers: list = []
        for idx, session in enumerate(self._sessions):
            mux = self._muxes[idx] if idx < len(self._muxes) else None
            label = self._session_labels[idx] if idx < len(self._session_labels) else f"session-{idx}"
            listen_endpoint = self._overlay_listen_label(label, session)
            m = self._session_metrics_snapshot(session)
            udp_rows: list = []
            tcp_rows: list = []
            if mux is not None:
                snap = mux.snapshot_connections()
                udp_rows = list(snap.get("udp", []))
                tcp_rows = list(snap.get("tcp", []))
            overlay_rows = []
            with contextlib.suppress(Exception):
                getter = getattr(session, "get_overlay_peers_snapshot", None)
                if callable(getter):
                    overlay_rows = list(getter() or [])

            if overlay_rows:
                for p in overlay_rows:
                    if bool(p.get("listening")):
                        listener_session = getattr(session, "inner_session", None)
                        listener_metrics = self._session_metrics_snapshot(listener_session)
                        peers.append({
                            "id": f"{idx}:{p.get('peer_id', 0)}",
                            "transport": label,
                            "state": "listening",
                            "connected": False,
                            "listen": listen_endpoint,
                            "peer": p.get("peer"),
                            "rtt_est_ms": p.get("rtt_est_ms", listener_metrics.rtt_est_ms),
                            "inflight": listener_metrics.inflight,
                            "decode_errors": 0,
                            "open_connections": {
                                "udp": 0,
                                "tcp": 0,
                            },
                            "traffic": {
                                "rx_bytes": 0,
                                "tx_bytes": 0,
                            },
                            "myudp": self._session_retransmit_stats(listener_session),
                        })
                        continue
                    row_session = session
                    server_peers = getattr(session, "_server_peers", None)
                    if isinstance(server_peers, dict):
                        ctx = server_peers.get(int(p.get("peer_id", 0)))
                        if isinstance(ctx, dict) and ctx.get("session") is not None:
                            row_session = ctx.get("session")
                    row_metrics = self._session_metrics_snapshot(row_session, fallback=m)
                    mux_chans = set(int(c) for c in (p.get("mux_chans") or []))
                    p_rx = 0
                    p_tx = 0
                    udp_open = 0
                    tcp_open = 0
                    for row in udp_rows:
                        chan_id = row.get("chan_id")
                        if chan_id is None:
                            continue
                        if str(row.get("state", "connected")).lower() == "listening":
                            continue
                        if mux_chans and chan_id not in mux_chans:
                            continue
                        st = row.get("stats", {})
                        p_rx += int(st.get("rx_bytes", 0) or 0)
                        p_tx += int(st.get("tx_bytes", 0) or 0)
                        udp_open += 1
                    for row in tcp_rows:
                        chan_id = row.get("chan_id")
                        if chan_id is None:
                            continue
                        if str(row.get("state", "connected")).lower() == "listening":
                            continue
                        if mux_chans and chan_id not in mux_chans:
                            continue
                        st = row.get("stats", {})
                        p_rx += int(st.get("rx_bytes", 0) or 0)
                        p_tx += int(st.get("tx_bytes", 0) or 0)
                        tcp_open += 1

                    row_connected = bool(p.get("connected", session.is_connected()))
                    row_state = str(p.get("state") or ("connected" if row_connected else "connecting"))
                    peers.append({
                        "id": f"{idx}:{p.get('peer_id', 0)}",
                        "transport": label,
                        "state": row_state,
                        "connected": row_connected,
                        "listen": listen_endpoint,
                        "peer": p.get("peer"),
                        "rtt_est_ms": p.get("rtt_est_ms", row_metrics.rtt_est_ms),
                        "inflight": row_metrics.inflight,
                        "decode_errors": 0,
                        "open_connections": {
                            "udp": udp_open,
                            "tcp": tcp_open,
                        },
                        "traffic": {
                            "rx_bytes": p_rx,
                            "tx_bytes": p_tx,
                        },
                        "myudp": self._session_retransmit_stats(row_session),
                    })
                continue

            rx_bytes = 0
            tx_bytes = 0
            for row in udp_rows + tcp_rows:
                st = row.get("stats", {})
                rx_bytes += int(st.get("rx_bytes", 0) or 0)
                tx_bytes += int(st.get("tx_bytes", 0) or 0)
            peer_label = None
            with contextlib.suppress(Exception):
                if hasattr(session, "peer_proto") and getattr(session, "peer_proto"):
                    pa = getattr(getattr(session, "peer_proto"), "send_port").peer_addr
                    if pa:
                        peer_label = f"{pa[0]}:{pa[1]}"
            with contextlib.suppress(Exception):
                if not peer_label and hasattr(session, "_peer_host") and hasattr(session, "_peer_port"):
                    host = str(getattr(session, "_peer_host") or "")
                    port = int(getattr(session, "_peer_port") or 0)
                    if host and port > 0:
                        peer_label = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
            decode_errors = 0
            with contextlib.suppress(Exception):
                pp = getattr(session, "peer_proto", None)
                if pp is not None:
                    decode_errors = int(getattr(pp, "unidentified_frames", 0) or 0)
            peers.append({
                "id": idx,
                "transport": label,
                "state": "connected" if bool(session.is_connected()) else "connecting",
                "connected": bool(session.is_connected()),
                "listen": listen_endpoint,
                "peer": peer_label,
                "rtt_est_ms": m.rtt_est_ms,
                "inflight": m.inflight,
                "decode_errors": decode_errors,
                "open_connections": {
                    "udp": len(udp_rows),
                    "tcp": len(tcp_rows),
                },
                "traffic": {
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                },
                "myudp": self._session_retransmit_stats(session),
            })
        return {"peers": peers, "count": len(peers)}

    def _group_config_snapshot(self, config: dict) -> dict:
        sections = getattr(self.args, "_config_sections", {}) or {}
        if not isinstance(sections, dict) or not sections:
            return dict(config)
        grouped: dict = {}
        assigned: set = set()
        for section in sorted(sections.keys()):
            keys = sections.get(section, []) or []
            block = {}
            for key in keys:
                if key in config:
                    block[key] = config[key]
            if block:
                grouped[section] = block
                assigned.update(block.keys())
        misc = {k: v for k, v in config.items() if k not in assigned}
        if misc:
            grouped["misc"] = misc
        return grouped

    def save_runtime_config(self) -> tuple[bool, str]:
        cfg_path = getattr(self.args, "config", None)
        if not cfg_path:
            return (True, "")
        try:
            path = pathlib.Path(str(cfg_path))
            payload = self._group_config_snapshot(self.get_config_snapshot(include_secrets=True))
            parent = path.parent
            if parent and str(parent) not in ("", "."):
                parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
            tmp.replace(path)
        except Exception as e:
            return (False, f"failed to persist config to {cfg_path}: {e}")
        return (True, "")

    def update_config(self, updates: dict) -> tuple[bool, str]:
        if not isinstance(updates, dict):
            return (False, "updates must be an object")
        for key, value in updates.items():
            if not hasattr(self.args, key):
                return (False, f"unknown config key: {key}")
            cur = getattr(self.args, key)
            if key in AdminWebUI._secret_config_keys():
                if not isinstance(value, str):
                    return (False, f"{key} expects string")
                setattr(self.args, key, value)
                continue
            if isinstance(cur, bool):
                if not isinstance(value, bool):
                    return (False, f"{key} expects boolean")
            elif isinstance(cur, int) and not isinstance(cur, bool):
                if not isinstance(value, int):
                    return (False, f"{key} expects integer")
            elif isinstance(cur, float):
                if not isinstance(value, (int, float)):
                    return (False, f"{key} expects number")
                value = float(value)
            elif isinstance(cur, str):
                if not isinstance(value, str):
                    return (False, f"{key} expects string")
            elif isinstance(cur, list):
                if not isinstance(value, list):
                    return (False, f"{key} expects list")
            elif cur is None:
                if not isinstance(value, (str, int, float, bool, list, dict)) and value is not None:
                    return (False, f"{key} has unsupported type")
            setattr(self.args, key, value)
        return self.save_runtime_config()

    def request_shutdown(self, exit_code: Optional[int] = None) -> None:
        if exit_code is not None:
            self._shutdown_exit_code = int(exit_code)
            self.log.debug("[SERVER] Runner shutdown requested rc=%d", self._shutdown_exit_code)
        else:
            self.log.debug("[SERVER] Runner shutdown requested")
        self._stop_requested = True
        if self._stop is not None:
            self._stop.set()

    async def _client_restart_watchdog(self) -> None:
        assert self._stop is not None
        assert self._restart_requested is not None
        try:
            while not self._stop.is_set():
                await asyncio.sleep(1.0)

                # Disabled by CLI
                timeout_s = float(getattr(self.args, "client_restart_if_disconnected", 0.0) or 0.0)
                if timeout_s <= 0:
                    continue

                # Only for configured peer clients
                if not _has_configured_overlay_peer(self.args):
                    continue

                # Need a live session object
                sess = self._session_obj
                if sess is None:
                    continue

                # Do nothing if already stopping or restart already requested
                if self._restart_requested.is_set() or self._stop.is_set():
                    continue

                # If connected, watchdog is idle
                if sess.is_connected():
                    continue

                # No disconnect timestamp yet -> initialize defensively
                if self._last_disconnected_monotonic is None:
                    self._last_disconnected_monotonic = time.monotonic()
                    continue

                down_for = time.monotonic() - self._last_disconnected_monotonic
                if down_for < timeout_s:
                    continue

                self.log.warning(
                    "[RUNNER] client disconnected for %.1fs (threshold %.1fs); requesting restart",
                    down_for,
                    timeout_s,
                )
                self.request_restart()
                return

        except asyncio.CancelledError:
            return
        except Exception as e:
            self.log.exception("[RUNNER] client restart watchdog failed: %r", e)

    # ---------- Runner-scoped CLI registrar ----------
    @staticmethod
    def register_overlay_cli(p: argparse.ArgumentParser) -> None:
        """
        Select the overlay transport (Session) used between peers.
        Default keeps current behavior: 'myudp'.
        """
        def _has(opt: str) -> bool:
            try:
                return any(opt in a.option_strings for a in p._actions)
            except Exception:
                return False
        if not _has('--overlay-transport'):
            p.add_argument(
                '--overlay-transport',
                default='myudp',
                help="Overlay transport between peers: "
                     "comma-separated list from myudp,tcp,quic,ws. "
                     "Multiple transports are supported simultaneously for listening instances."
            )
        for proto in ("tcp", "quic", "ws"):
            bind_opt = f"--{proto}-bind"
            listen_port_opt = f"--{proto}-own-port"
            peer_opt = f"--{proto}-peer"
            peer_port_opt = f"--{proto}-peer-port"
            if not _has(bind_opt):
                p.add_argument(bind_opt, default='::', help=f'{proto.upper()} overlay bind address')
            if not _has(listen_port_opt):
                default_port = {"tcp": 8081, "quic": 443, "ws": 8080}[proto]
                p.add_argument(listen_port_opt, dest=f"{proto}_own_port", type=int, default=default_port, help=f'{proto.upper()} overlay own port')
            if not _has(peer_opt):
                p.add_argument(peer_opt, default=None, help=f'{proto.upper()} peer IP/FQDN')
            if not _has(peer_port_opt):
                default_peer_port = {"tcp": 8081, "quic": 443, "ws": 8080}[proto]
                p.add_argument(peer_port_opt, type=int, default=default_peer_port, help=f'{proto.upper()} peer overlay port')
        if not _has('--client-restart-if-disconnected'):
            p.add_argument(
                '--client-restart-if-disconnected',
                type=float,
                default=0.0,
                help='If configured as a peer client (for example --udp-peer set) and overlay stays disconnected for this many seconds, request process restart. 0 disables.'
            )            
    @staticmethod
    def _parse_overlay_transports(args: argparse.Namespace) -> List[str]:
        raw = str(getattr(args, "overlay_transport", "myudp") or "myudp")
        parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
        if not parts:
            parts = ["myudp"]
        allowed = {"myudp", "tcp", "quic", "ws"}
        bad = [p for p in parts if p not in allowed]
        if bad:
            raise ValueError(f"Unsupported overlay transport(s): {', '.join(sorted(set(bad)))}")
        seen: List[str] = []
        for part in parts:
            if part not in seen:
                seen.append(part)
        if len(seen) > 1 and any(_has_configured_overlay_peer(args, transport=t) for t in seen):
            raise ValueError("Multiple --overlay-transport values are currently supported only for listening instances without configured transport peers.")
        return seen

    @staticmethod
    def _overlay_port_for(args: argparse.Namespace, transport: str, multi_count: int) -> int:
        listen_attr = _overlay_cli_attrs(transport)[3]
        base_default = {"myudp": 4433, "tcp": 8081, "quic": 443, "ws": 8080}[transport]
        return int(getattr(args, listen_attr, base_default))

    @staticmethod
    def build_sessions_from_overlay(args: argparse.Namespace) -> List[Tuple[str, ISession]]:
        """
        Return the ISession(s) that implement the chosen overlay transport(s).
        """
        out: List[Tuple[str, ISession]] = []
        choices = Runner._parse_overlay_transports(args)
        for choice in choices:
            session_args = argparse.Namespace(**vars(args))
            session_args.overlay_transport = choice
            bind_attr, peer_attr, peer_port_attr, listen_port_attr = _overlay_cli_attrs(choice)
            session_args.bind443 = getattr(session_args, bind_attr, "::")
            session_args.peer = getattr(session_args, peer_attr, getattr(session_args, "peer", None))
            session_args.peer_port = int(getattr(session_args, peer_port_attr, getattr(session_args, "peer_port", 443)) or 443)
            setattr(session_args, listen_port_attr, Runner._overlay_port_for(args, choice, len(choices)))
            if choice == "tcp":
                out.append((choice, TcpStreamSession.from_args(session_args)))
            elif choice == "quic":
                out.append((choice, QuicSession.from_args(session_args)))
            elif choice == "ws":
                out.append((choice, WebSocketSession.from_args(session_args)))
            else:
                out.append((choice, UdpSession.from_args(session_args)))
        return out

# ------------ Admin Webinterface ------------

class AdminWebUI:
    AUTH_CHALLENGE_TTL_SEC = 90
    AUTH_SESSION_TTL_SEC = 8 * 60 * 60
    LIVE_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    LIVE_TOPICS = ("status", "connections", "peers", "meta")

    @staticmethod
    def register_cli(p):
        g = p.add_argument_group("admin_web")
        g.add_argument(
            "--admin-web",
            action="store_true",
            default=True,
            help="Enable admin web interface",
        )
        g.add_argument(
            "--admin-web-bind",
            default="127.0.0.1",
            help="Bind address for admin web interface",
        )
        g.add_argument(
            "--admin-web-port",
            type=int,
            default=18080,
            help="Port for admin web interface",
        )
        g.add_argument(
            "--admin-web-path",
            default="/",
            help="Base path for admin web interface",
        )
        g.add_argument(
            "--admin-web-dir",
            default="./admin_web",
            help="Directory containing admin web files",
        )
        g.add_argument(
            "--admin-web-name",
            default="",
            help="Optional instance name shown in the admin web title and headline",
        )
        g.add_argument(
            "--admin-web-token",
            default="",
            help="Optional bearer token for admin restart endpoint",
        )
        g.add_argument(
            "--admin-web-auth-disable",
            action="store_true",
            default=False,
            help="Disable username/password challenge for admin web access",
        )
        g.add_argument(
            "--admin-web-username",
            default="",
            help="Username for admin web access when challenge-based authentication is enabled",
        )
        g.add_argument(
            "--admin-web-password",
            default="",
            help="Password for admin web access when challenge-based authentication is enabled",
        )

    def __init__(self, args, runner):
        self.args = args
        self.runner = runner
        self.server = None
        self.log = logging.getLogger("admin_web")
        DebugLoggingConfigurator.debug_logger_status(self.log)
        self.started_monotonic = time.monotonic()
        self._auth_challenges: Dict[str, dict] = {}
        self._auth_sessions: Dict[str, float] = {}

    async def start(self):
        if not getattr(self.args, "admin_web", False):
            return

        self.server = await asyncio.start_server(
            self._handle_client,
            host=self.args.admin_web_bind,
            port=self.args.admin_web_port,
        )

        self.log.info(
            "Admin web UI listening on http://%s:%d%s",
            self.args.admin_web_bind,
            self.args.admin_web_port,
            self.args.admin_web_path,
        )

    async def stop(self):
        self.log.info(
            "Admin web UI stopping")
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def _handle_client(self, reader, writer):
        self.log.debug(
            "Admin web UI handling")
        try:
            reqline = await reader.readline()
            if not reqline:
                return

            self.log.debug(
                "Request %s",reqline)

            parts = reqline.decode("utf-8", "replace").strip().split()
            if len(parts) != 3:
                await self._send(writer, 400, b"Bad Request", "text/plain; charset=utf-8")
                return

            method, raw_path, _httpver = parts
            headers = {}

            content_length = 0
            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break
                text = line.decode("utf-8", "replace")
                if ":" in text:
                    k, v = text.split(":", 1)
                    hk = k.strip().lower()
                    hv = v.strip()
                    headers[hk] = hv
                    if hk == "content-length":
                        with contextlib.suppress(Exception):
                            content_length = max(0, int(hv))

            body = b""
            if content_length > 0:
                body = await reader.readexactly(content_length)

            path = raw_path.split("?", 1)[0]
            self.log.info("ADMIN REQUEST method=%s path=%s", method, path)

            if (
                method == "GET"
                and path == "/api/live"
                and str(headers.get("upgrade", "")).strip().lower() == "websocket"
            ):
                if not self._is_authenticated(headers):
                    payload = {"ok": False, "authenticated": False, "error": "authentication required"}
                    self._log_api_response(path, 401, payload, summary="auth required")
                    await self._send_json(writer, 401, payload)
                    return
                await self._handle_live_websocket(reader, writer, headers)
                return

            if path == "/api/auth/state":
                await self._handle_auth_state(writer, headers)
                return

            if path == "/api/auth/challenge":
                await self._handle_auth_challenge(writer, method)
                return

            if path == "/api/auth/login":
                await self._handle_auth_login(writer, method, body)
                return

            if path == "/api/auth/logout":
                await self._handle_auth_logout(writer, method, headers)
                return

            if path.startswith("/api/") and not self._is_authenticated(headers):
                payload = {"ok": False, "authenticated": False, "error": "authentication required"}
                self._log_api_response(path, 401, payload, summary="auth required")
                await self._send_json(writer, 401, payload)
                return

            if path == "/api/health":
                payload={"ok": True}
                self._log_api_response("/api/health", 200, payload)
                await self._send_json(writer, 200, payload)
                return

            if path == "/api/meta":                
                await self._handle_meta(writer)
                return

            if path == "/api/restart":
                await self._handle_restart(writer, method, headers)
                return

            if path == "/api/shutdown":
                await self._handle_shutdown(writer, method, headers)
                return

            if path == "/api/status":
                await self._handle_status(writer)
                return

            if path == "/api/connections":
                await self._handle_connections(writer)
                return

            if path == "/api/config":
                await self._handle_config(writer, method, body)
                return

            if path == "/api/logs":
                await self._handle_logs(writer, raw_path)
                return

            if path == "/api/peers":
                await self._handle_peers(writer)
                return

            await self._handle_static(writer, path)

        except Exception:            
            self.log.exception("Admin web request failed")
            with contextlib.suppress(Exception):
                await self._send(writer, 500, b"Internal Server Error", "text/plain; charset=utf-8")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    def _build_connections_payload(self) -> dict:
        payload = self.runner.get_connections_snapshot()
        payload["app"] = "udp-bidirectional-mux"
        payload["milestone"] = "C"
        return payload

    async def _handle_connections(self, writer):
        payload = self._build_connections_payload()
        self._log_api_response("/api/connections", 200, payload)
        await self._send_json(writer, 200, payload)

    def _build_meta_payload(self) -> dict:
        return {
            "app": "udp-bidirectional-mux",
            "pid": os.getpid(),
            "uptime_sec": int(time.monotonic() - self.started_monotonic),
            "admin_web_name": str(getattr(self.runner.args, "admin_web_name", "") or ""),
            "overlay_transport": getattr(self.runner.args, "overlay_transport", None),
            "dashboard_enabled": getattr(self.runner.args, "dashboard", None),
            "milestone": "C",
        }

    async def _handle_meta(self, writer):
        payload = self._build_meta_payload()
        self._log_api_response("/api/meta", 200, payload)
        await self._send_json(writer, 200, payload)

    async def _handle_config(self, writer, method: str, body: bytes):
        if method == "GET":
            payload = {
                "ok": True,
                "config": self.runner.get_config_snapshot(),
                "schema": self.runner.get_config_schema_snapshot(),
            }
            self._log_api_response("/api/config", 200, payload, summary="config snapshot")
            await self._send_json(writer, 200, payload)
            return

        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        updates = req.get("updates", {})
        ok, err = self.runner.update_config(updates)
        if not ok:
            await self._send_json(writer, 400, {"ok": False, "error": err})
            return
        if any(key in AdminWebUI._secret_config_keys() or key in {"admin_web_auth_disable", "admin_web_username"} for key in updates.keys()):
            self.reset_auth_state()
        payload = {"ok": True, "config": self.runner.get_config_snapshot()}
        self._log_api_response("/api/config", 200, payload, summary=f"updated keys={list(updates.keys())}")
        await self._send_json(writer, 200, payload)

    async def _handle_logs(self, writer, raw_path: str):
        limit = 400
        with contextlib.suppress(Exception):
            if "?" in raw_path:
                query = raw_path.split("?", 1)[1]
                for pair in query.split("&"):
                    if not pair:
                        continue
                    k, _, v = pair.partition("=")
                    if k == "limit":
                        limit = int(v)
                        break
        lines = self.runner.get_debug_logs(limit=limit)
        payload = {"ok": True, "lines": lines, "count": len(lines)}
        self._log_api_response("/api/logs", 200, payload, summary=f"count={len(lines)}")
        await self._send_json(writer, 200, payload)

    def _build_peers_payload(self) -> dict:
        payload = self.runner.get_peer_connections_snapshot()
        payload["ok"] = True
        return payload

    async def _handle_peers(self, writer):
        payload = self._build_peers_payload()
        self._log_api_response("/api/peers", 200, payload, summary=f"count={payload.get('count', 0)}")
        await self._send_json(writer, 200, payload)

    async def _handle_restart(self, writer, method, headers):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        token = getattr(self.args, "admin_web_token", "") or ""
        if token:
            auth = headers.get("authorization", "")
            expected = f"Bearer {token}"
            if auth != expected:
                await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
                return

        payload = {"ok": True, "restarting": True}
        self._log_api_response("/api/restart", 200, payload)
        await self._send_json(writer, 200, payload)
        self.runner.request_restart()

    async def _handle_shutdown(self, writer, method, headers):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return

        token = getattr(self.args, "admin_web_token", "") or ""
        if token:
            auth = headers.get("authorization", "")
            expected = f"Bearer {token}"
            if auth != expected:
                await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
                return

        payload = {"ok": True, "shutting_down": True}
        self._log_api_response("/api/shutdown", 200, payload)
        await self._send_json(writer, 200, payload)

        # let response flush before stopping (non-restart exit code)
        asyncio.get_running_loop().call_soon(self.runner.request_shutdown, 76)

    @staticmethod
    def _secret_config_keys() -> Set[str]:
        return {"admin_web_password"}

    def auth_required(self) -> bool:
        if bool(getattr(self.args, "admin_web_auth_disable", False)):
            return False
        username = str(getattr(self.args, "admin_web_username", "") or "")
        password = str(getattr(self.args, "admin_web_password", "") or "")
        return bool(username and password)

    def reset_auth_state(self) -> None:
        self._auth_challenges.clear()
        self._auth_sessions.clear()

    def _prune_auth_state(self) -> None:
        now = time.time()
        expired_challenges = [key for key, item in self._auth_challenges.items() if float(item.get("expires_at", 0.0)) <= now]
        for key in expired_challenges:
            self._auth_challenges.pop(key, None)
        expired_sessions = [key for key, expires_at in self._auth_sessions.items() if float(expires_at) <= now]
        for key in expired_sessions:
            self._auth_sessions.pop(key, None)

    def _parse_cookie_header(self, headers: dict) -> Dict[str, str]:
        raw = str(headers.get("cookie", "") or "")
        cookies: Dict[str, str] = {}
        for part in raw.split(";"):
            item = part.strip()
            if not item or "=" not in item:
                continue
            key, value = item.split("=", 1)
            cookies[key.strip()] = value.strip()
        return cookies

    def _session_cookie_name(self) -> str:
        scope = "|".join([
            str(getattr(self.args, "admin_web_bind", "") or ""),
            str(getattr(self.args, "admin_web_port", "") or ""),
            str(getattr(self.args, "admin_web_path", "") or ""),
        ])
        suffix = hashlib.sha256(scope.encode("utf-8")).hexdigest()[:12]
        return f"admin_web_session_{suffix}"

    def _is_authenticated(self, headers: dict) -> bool:
        if not self.auth_required():
            return True
        self._prune_auth_state()
        token = self._parse_cookie_header(headers).get(self._session_cookie_name(), "")
        return bool(token and token in self._auth_sessions)

    def _build_auth_seed(self, challenge_id: str) -> str:
        return secrets.token_hex(32) + challenge_id

    def _build_auth_response(self, seed: str, username: str, password: str) -> str:
        msg = f"{seed}:{username}:{password}".encode("utf-8")
        return hashlib.sha256(msg).hexdigest()

    def _issue_session_headers(self) -> List[Tuple[str, str]]:
        token = secrets.token_hex(32)
        self._auth_sessions[token] = time.time() + self.AUTH_SESSION_TTL_SEC
        cookie = f"{self._session_cookie_name()}={token}; Path=/; HttpOnly; SameSite=Strict"
        return [("Set-Cookie", cookie)]

    async def _handle_auth_state(self, writer, headers: dict):
        payload = {
            "ok": True,
            "auth_required": self.auth_required(),
            "authenticated": self._is_authenticated(headers),
        }
        self._log_api_response("/api/auth/state", 200, payload)
        await self._send_json(writer, 200, payload)

    async def _handle_auth_challenge(self, writer, method: str):
        if method != "GET":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": True, "auth_required": False}
            self._log_api_response("/api/auth/challenge", 200, payload, summary="auth disabled")
            await self._send_json(writer, 200, payload)
            return
        self._prune_auth_state()
        challenge_id = secrets.token_hex(16)
        seed = self._build_auth_seed(challenge_id)
        self._auth_challenges[challenge_id] = {
            "seed": seed,
            "expires_at": time.time() + self.AUTH_CHALLENGE_TTL_SEC,
        }
        payload = {
            "ok": True,
            "auth_required": True,
            "challenge_id": challenge_id,
            "seed": seed,
            "algorithm": "sha256(seed:username:password)",
        }
        self._log_api_response("/api/auth/challenge", 200, {"ok": True, "auth_required": True}, summary="issued challenge")
        await self._send_json(writer, 200, payload)

    async def _handle_auth_login(self, writer, method: str, body: bytes):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        if not self.auth_required():
            payload = {"ok": True, "auth_required": False, "authenticated": True}
            await self._send_json(writer, 200, payload, headers=self._issue_session_headers())
            return
        try:
            req = json.loads((body or b"{}").decode("utf-8"))
        except Exception:
            await self._send_json(writer, 400, {"ok": False, "error": "invalid JSON body"})
            return
        challenge_id = str(req.get("challenge_id", "") or "")
        proof = str(req.get("proof", "") or "").strip().lower()
        self._prune_auth_state()
        challenge = self._auth_challenges.pop(challenge_id, None)
        if not challenge:
            payload = {"ok": False, "authenticated": False, "error": "invalid or expired challenge"}
            self._log_api_response("/api/auth/login", 403, payload, summary="invalid challenge")
            await self._send_json(writer, 403, payload)
            return
        expected = self._build_auth_response(
            str(challenge.get("seed", "") or ""),
            str(getattr(self.args, "admin_web_username", "") or ""),
            str(getattr(self.args, "admin_web_password", "") or ""),
        )
        if proof != expected:
            payload = {"ok": False, "authenticated": False, "error": "authentication failed"}
            self._log_api_response("/api/auth/login", 403, payload, summary="bad proof")
            await self._send_json(writer, 403, payload)
            return
        payload = {"ok": True, "authenticated": True}
        self._log_api_response("/api/auth/login", 200, payload, summary="authenticated")
        await self._send_json(writer, 200, payload, headers=self._issue_session_headers())

    async def _handle_auth_logout(self, writer, method: str, headers: dict):
        if method != "POST":
            await self._send(writer, 405, b"Method Not Allowed", "text/plain; charset=utf-8")
            return
        token = self._parse_cookie_header(headers).get(self._session_cookie_name(), "")
        if token:
            self._auth_sessions.pop(token, None)
        payload = {"ok": True, "authenticated": False}
        self._log_api_response("/api/auth/logout", 200, payload)
        await self._send_json(
            writer,
            200,
            payload,
            headers=[("Set-Cookie", f"{self._session_cookie_name()}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")],
        )

    async def _handle_static(self, writer, req_path):
        base = pathlib.Path(self.args.admin_web_dir).resolve()

        if req_path in ("", "/"):
            req_path = "/index.html"

        # Milestone A: admin_web_path is accepted as CLI/config, but static routing
        # is intentionally kept simple. If you later want to support mounting below
        # /admin/ or similar, normalize req_path here.

        rel = req_path.lstrip("/")
        full = (base / rel).resolve()

        if not str(full).startswith(str(base)):
            await self._send(writer, 403, b"Forbidden", "text/plain; charset=utf-8")
            return

        if not full.exists() or not full.is_file():
            await self._send(writer, 404, b"Not Found", "text/plain; charset=utf-8")
            return

        data = full.read_bytes()
        ctype, _ = mimetypes.guess_type(str(full))
        await self._send(
            writer,
            200,
            data,
            ctype or "application/octet-stream",
        )

    def _build_status_payload(self) -> dict:
        payload = self.runner.get_status_snapshot()
        payload["admin_web_name"] = str(getattr(self.runner.args, "admin_web_name", "") or "")
        payload["uptime_sec"] = int(time.monotonic() - self.started_monotonic)
        payload["app"] = "udp-bidirectional-mux"
        payload["milestone"] = "B"
        return payload

    async def _handle_status(self, writer):
        payload = self._build_status_payload()
        self._log_api_response("/api/status", 200, payload)
        await self._send_json(writer, 200, payload)

    def _live_topic_interval_s(self, topic: str) -> float:
        t = str(topic or "").strip().lower()
        if t == "meta":
            return 5.0
        return 1.0

    def _live_topic_payload(self, topic: str) -> Optional[dict]:
        t = str(topic or "").strip().lower()
        if t == "status":
            return self._build_status_payload()
        if t == "connections":
            return self._build_connections_payload()
        if t == "peers":
            return self._build_peers_payload()
        if t == "meta":
            return self._build_meta_payload()
        return None

    def _parse_live_topics(self, value: Any) -> Set[str]:
        topics: Set[str] = set()
        if isinstance(value, str):
            value = [value]
        if isinstance(value, (list, tuple, set)):
            for item in value:
                topic = str(item or "").strip().lower()
                if topic in self.LIVE_TOPICS:
                    topics.add(topic)
        return topics

    async def _handle_live_websocket(self, reader, writer, headers: dict) -> None:
        key = str(headers.get("sec-websocket-key", "") or "").strip()
        version = str(headers.get("sec-websocket-version", "") or "").strip()
        if not key or version != "13":
            await self._send(writer, 400, b"Bad WebSocket Request", "text/plain; charset=utf-8")
            return
        accept = base64.b64encode(
            hashlib.sha1((key + self.LIVE_WS_GUID).encode("utf-8")).digest()
        ).decode("ascii")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(response)
        await writer.drain()

        topics: Set[str] = {"status", "connections", "peers", "meta"}
        next_due: Dict[str, float] = {topic: 0.0 for topic in self.LIVE_TOPICS}
        await self._send_ws_json(
            writer,
            {
                "type": "hello",
                "topics": sorted(topics),
                "intervals_sec": {topic: self._live_topic_interval_s(topic) for topic in self.LIVE_TOPICS},
            },
        )
        while True:
            now = time.monotonic()
            if topics:
                wait_s = min(max(0.0, next_due.get(topic, 0.0) - now) for topic in topics)
            else:
                wait_s = 30.0
            incoming = None
            try:
                incoming = await asyncio.wait_for(self._recv_ws_message(reader, writer), timeout=wait_s)
            except asyncio.TimeoutError:
                incoming = None
            if incoming is False:
                return
            if isinstance(incoming, str):
                try:
                    msg = json.loads(incoming)
                except Exception:
                    msg = {}
                requested = self._parse_live_topics(msg.get("subscribe"))
                if requested:
                    topics = requested
                active_tabs = set(str(item or "").strip().lower() for item in (msg.get("active_tabs") or []))
                if active_tabs:
                    next_topics: Set[str] = {"status"}
                    if "status" in active_tabs:
                        next_topics.update({"connections", "peers"})
                    if "misc" in active_tabs:
                        next_topics.add("meta")
                    topics = next_topics
                request_topics = self._parse_live_topics(msg.get("request"))
                for topic in sorted(request_topics):
                    payload = self._live_topic_payload(topic)
                    if payload is None:
                        continue
                    await self._send_ws_json(writer, {"type": topic, "data": payload})
                    next_due[topic] = time.monotonic() + self._live_topic_interval_s(topic)
            now = time.monotonic()
            for topic in sorted(topics):
                if now < next_due.get(topic, 0.0):
                    continue
                payload = self._live_topic_payload(topic)
                if payload is None:
                    continue
                await self._send_ws_json(writer, {"type": topic, "data": payload})
                next_due[topic] = now + self._live_topic_interval_s(topic)

    async def _recv_ws_message(self, reader, writer) -> Any:
        try:
            hdr = await reader.readexactly(2)
        except asyncio.IncompleteReadError:
            return False
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            ext = await reader.readexactly(2)
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = await reader.readexactly(8)
            length = struct.unpack("!Q", ext)[0]
        mask_key = await reader.readexactly(4) if masked else b""
        payload = await reader.readexactly(length) if length else b""
        if masked and mask_key:
            payload = bytes(b ^ mask_key[idx % 4] for idx, b in enumerate(payload))
        if opcode == 0x8:
            with contextlib.suppress(Exception):
                await self._send_ws_frame(writer, 0x8, payload)
            return False
        if opcode == 0x9:
            with contextlib.suppress(Exception):
                await self._send_ws_frame(writer, 0xA, payload)
            return None
        if opcode == 0xA:
            return None
        if opcode != 0x1:
            return None
        return payload.decode("utf-8", "replace")

    async def _send_ws_json(self, writer, obj: dict) -> None:
        await self._send_ws_frame(
            writer,
            0x1,
            json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        )

    async def _send_ws_frame(self, writer, opcode: int, payload: bytes = b"") -> None:
        data = payload or b""
        first = 0x80 | (opcode & 0x0F)
        length = len(data)
        if length < 126:
            header = bytes([first, length])
        elif length < (1 << 16):
            header = bytes([first, 126]) + struct.pack("!H", length)
        else:
            header = bytes([first, 127]) + struct.pack("!Q", length)
        writer.write(header + data)
        await writer.drain()

    def _json_one_line(self, payload) -> str:
        try:
            txt = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except Exception as e:
            txt = f"<json-encode-failed {e!r}>"
        if len(txt) > 4000:
            txt = txt[:4000] + "...<truncated>"
        return txt

    def _log_api_response(self, path: str, status: int, payload, *, summary: Optional[str] = None) -> None:
        if summary:
            self.log.info(
                "ADMIN RESPONSE path=%s status=%d summary=%s payload=%s",
                path,
                status,
                summary,
                self._json_one_line(payload),
            )
        else:
            self.log.info(
                "ADMIN RESPONSE path=%s status=%d payload=%s",
                path,
                status,
                self._json_one_line(payload),
            )

    async def _send_json(self, writer, code, obj, headers: Optional[List[Tuple[str, str]]] = None):
        data = json.dumps(obj, indent=2).encode("utf-8")
        await self._send(writer, code, data, "application/json; charset=utf-8", headers=headers)

    async def _send(self, writer, code, data, content_type, headers: Optional[List[Tuple[str, str]]] = None):
        reason = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(code, "OK")

        hdr = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(data)}\r\n"
            f"Connection: close\r\n"
            f"Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
            f"Pragma: no-cache\r\n"
            f"Expires: 0\r\n"
        )
        extra = ""
        for key, value in (headers or []):
            extra += f"{key}: {value}\r\n"
        hdr = (hdr + extra + "\r\n").encode("utf-8")

        writer.write(hdr + data)
        await writer.drain()


# ------------ CLI ------------
# ============================ ConfigAwareCLI (JSON) ===========================
import os, json, argparse, pathlib, sys
from typing import Any, Dict, List, Tuple, Callable, Optional, Set

class ConfigAwareCLI:
    """
    JSON-only, stdlib-only config layer around argparse that:
      - bootstraps --config / --dump-config [/ format] / --save-config / --save-format / --force
      - registers options via provided (section_name, register_fn) list
      - applies JSON as argparse defaults by inspecting argparse actions (no duplication)
      - tracks which dests each registrar added for grouped dumps
      - can print or save the effective configuration and EXIT gracefully by itself
      - supports a human-readable dump that comments out unchanged values and shows descriptions
    """

    def __init__(self, *, description: str) -> None:
        self.description = description
        self._sections: Dict[str, Set[str]] = {}
        self._bootstrap: Optional[argparse.ArgumentParser] = None
        self._parser: Optional[argparse.ArgumentParser] = None
        self._raw_config: Optional[Dict[str, Any]] = None

        # Snapshots captured right AFTER registrars add their options,
        # and BEFORE we apply any JSON config.
        self._baseline_defaults: Dict[str, Any] = {}
        self._action_help: Dict[str, str] = {}
        self._action_choices: Dict[str, List[Any]] = {}

    # ---------- public surface ----------
    def parse_args(
        self,
        argv: Optional[List[str]],
        registrars: List[Tuple[str, Callable[[argparse.ArgumentParser], None]]],
    ) -> argparse.Namespace:
        # Phase 0: bootstrap to get config & dump/save wants
        boot_args, remaining = self._parse_bootstrap(argv)
        argv_list = list(argv) if argv is not None else sys.argv[1:]
        explicit_config_flag = any(a in ("-c", "--config") for a in argv_list)

        # Phase 1: build full parser and register CLI from single source of truth
        parser = self._build_full_parser(registrars)

        # Phase 2: apply JSON config as defaults (if provided)
        if boot_args.config:
            config_path = pathlib.Path(boot_args.config)
            if explicit_config_flag or config_path.exists():
                try:
                    cfg = self._load_json_config(boot_args.config)
                except FileNotFoundError:
                    # Missing config should not prevent startup; continue with
                    # built-in argparse defaults unless a readable config exists.
                    sys.stderr.write(
                        f"Config file not found, continuing with defaults: {config_path}\n"
                    )
                    sys.stderr.flush()
                else:
                    self._raw_config = cfg
                    self._apply_config_defaults_from_json(parser, cfg)

        # Phase 3: final parse; CLI overrides config/defaults
        args = parser.parse_args(remaining)

        # Promote bootstrap flags to final args for convenience
        args.config = boot_args.config
        args.dump_config = boot_args.dump_config       # "human" | "json" | "json-flat" | None
        args.save_config = boot_args.save_config       # file path or None
        args.save_format = boot_args.save_format       # "json" | "json-flat"
        args.force = boot_args.force                   # bool

        # If dumping or saving was requested, perform it and exit right here.
        self._maybe_dump_or_save_and_exit(args)

        #Tweak loggers
        self._apply_per_section_overrides(args)

        return args

    def dump_effective_config_json(self, args: argparse.Namespace) -> str:
        """
        Serialize effective args (post-parse) to JSON, grouped by registrars.
        (Useful if you prefer to call it manually; not needed for --dump-config.)
        """
        grouped = self._group_effective(self._effective_dict(vars(args)))
        return json.dumps(grouped, indent=2, ensure_ascii=False) + "\n"

    @property
    def sections(self) -> Dict[str, Set[str]]:
        return self._sections

    # ---------- internal: bootstrap / build ----------
    def _parse_bootstrap(self, argv: Optional[List[str]]):
        p = argparse.ArgumentParser(add_help=False)
        p.add_argument("--config", "-c", default="ObstacleBridge.cfg",
                       help="Path to a JSON config file. Values become defaults that CLI can override.")
        # Optional argument: if omitted -> const="human"
        p.add_argument("--dump-config", nargs="?", const="human",
                       choices=("human", "json", "json-flat"),
                       help="Dump effective configuration and exit. "
                            "Default format is 'human'; others: 'json', 'json-flat'.")
        p.add_argument("--save-config", metavar="FILE", default=None,
                       help="Write effective configuration to FILE and exit (JSON).")
        p.add_argument("--save-format", choices=("json", "json-flat"), default="json",
                       help="Format used with --save-config (default: json = grouped/sectioned).")
        p.add_argument("--force", "-f", action="store_true",
                       help="Overwrite the target FILE if it already exists (with --save-config).")
        self._bootstrap = p
        return p.parse_known_args(argv)

    def _build_full_parser(self, registrars):
        p = argparse.ArgumentParser(
            description=self.description,
            parents=[self._bootstrap] if self._bootstrap else [],
            add_help=True,
        )

        sections = {}

        # 1) run all registrars and collect sections
        for section, registrar in registrars:
            before = {a.dest for a in p._actions if getattr(a, "dest", None)}
            registrar(p)
            after  = {a.dest for a in p._actions if getattr(a, "dest", None)}
            new_dests = {d for d in (after - before) if d and d != "help"}
            if new_dests:
                sections.setdefault(section, set()).update(new_dests)

        # 2) Add auto-generated per-section log options
        for section in sections.keys():
            opt_name = f"log_{section}"       # internal dest
            cli_flag = f"--log-{section.replace('_', '-')}"
            p.add_argument(cli_flag, dest=opt_name, default=None,
                        help=f"Override log level for component '{section}'")

            # 3) Add them directly into the SAME section
            sections[section].add(opt_name)

        # 4) Snapshot defaults + help text (now that all options exist)
        self._baseline_defaults = {}
        self._action_help = {}
        self._action_choices = {}
        for a in p._actions:
            d = getattr(a, "dest", None)
            if not d or d == "help":
                continue
            self._baseline_defaults[d] = getattr(a, "default", None)
            self._action_help[d] = getattr(a, "help", "") or "(no description)"
            choices = getattr(a, "choices", None)
            if choices is not None:
                self._action_choices[d] = list(choices)

        self._sections = sections
        self._parser = p
        return p

    # ---------- internal: dump/save & formatting ----------
    def _apply_per_section_overrides(self, args: argparse.Namespace) -> None:
        import logging

        self._log_object_attributes(args)
        self._log_registered_loggers()

        # Keep third-party library logger names aligned with our section names.
        # Example: "log_ws_session" should also control websockets' own logger
        # hierarchy so the admin debug ring doesn't get flooded by frame dumps.
        logger_aliases = {
            "ws_session": ("websockets", "websockets.client", "websockets.server"),
        }

        # Automatic section → logger name mapping
        # All section loggers become: runner.<section>
        for key, val in vars(args).items():
            if not key.startswith("log_"):
                continue
            if not val:
                continue

            section = key[4:]
            logger_name = f"{section}"

            try:
                level = getattr(logging, val.upper())
            except Exception:
                continue

            lg = logging.getLogger(logger_name)
            lg.setLevel(level)

            DebugLoggingConfigurator.debug_logger_status(lg)

            for alias_name in logger_aliases.get(section, ()):
                alias_logger = logging.getLogger(alias_name)
                alias_logger.setLevel(level)
                DebugLoggingConfigurator.debug_logger_status(alias_logger)


    def _log_registered_loggers(self)  -> None:
        root = logging.getLogger()

        # Iterate through all registered logger objects
        for name, logger_obj in logging.Logger.manager.loggerDict.items():
            if isinstance(logger_obj, logging.Logger):
                root.info(f"Registered logger: {name}")
            else:
                root.info(f"Placeholder logger: {name}")


    def _log_object_attributes(self, args: argparse.Namespace)  -> None:
        """Log all attributes from vars(obj) into the root logger."""
        root = logging.getLogger()

        for key, value in vars(args).items():
            root.info(f"Key: {key} | Value: {value!r}")



    def _maybe_dump_or_save_and_exit(self, args: argparse.Namespace) -> None:
        """
        If --dump-config and/or --save-config were requested, perform the action(s) and sys.exit(0).
        """
        want_dump = bool(args.dump_config)
        want_save = bool(args.save_config)

        if not (want_dump or want_save):
            return

        # Build effective mappings
        eff_all = self._effective_dict(vars(args))
        grouped = self._group_effective(eff_all)        # sectioned (for human and json)
        flat    = self._flat_effective(eff_all)         # flat

        # (A) Dump
        if want_dump:
            fmt = args.dump_config  # "human" | "json" | "json-flat"
            if fmt == "human":
                text = self._format_human(grouped)
            elif fmt == "json":
                text = json.dumps(grouped, indent=2, ensure_ascii=False) + "\n"
            else:  # "json-flat"
                text = json.dumps(flat, indent=2, ensure_ascii=False) + "\n"
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                # Allow piping to commands that close early (e.g., `head`)
                pass

        # (B) Save
        if want_save:
            path = pathlib.Path(args.save_config)
            if path.exists() and not args.force:
                sys.stderr.write(f"Refusing to overwrite existing file: {path} (use --force)\n")
                sys.stderr.flush()
                sys.exit(2)
            fmt = args.save_format  # "json" | "json-flat"
            payload = grouped if fmt == "json" else flat
            with path.open("w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
            sys.stderr.write(f"Saved configuration to {path}\n")
            sys.stderr.flush()

        # We did what the user asked, so exit gracefully.
        sys.exit(0)

    def _format_human(self, grouped: Dict[str, Dict[str, Any]]) -> str:
        """
        Human-friendly dump formatted like a commented config:
          [section]
          # <description of param A>
          <param_a> : <value>         # active if value differs from built-in default
          # <description of param B>
          # <param_b> : <value>        # commented if value equals built-in default
        """
        lines: List[str] = []

        # Iterate sections deterministically
        for section in sorted(grouped.keys()):
            block = grouped[section]
            if not block:
                continue

            # Compute per-section alignment width
            key_width = max((len(k) for k in block.keys()), default=0)
            lines.append(f"[{section}]")

            # Stable key order inside section
            for k in sorted(block.keys()):
                effective_val = block[k]
                desc = (self._action_help.get(k) or "").strip()
                changed = self._is_changed_from_default(k, effective_val)

                # 1) Description line (always a comment)
                if desc:
                    for line in desc.splitlines():
                        lines.append(f";# {line}")
                else:
                    lines.append(";# (no description)")

                # 2) Parameter line
                rendered_val = self._repr_human(effective_val)
                default_val = self._baseline_defaults.get(k, None)
                rendered_default = self._repr_human(default_val)

                if changed:
                    # Active line + show built-in default
                    lines.append(f"{k.ljust(key_width)} = {rendered_val}  ; default is {rendered_default}")
                else:
                    # Commented line if unchanged (kept '=' for consistency)
                    lines.append(f"; {k.ljust(key_width)} = {rendered_val}")

            # blank line between sections
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def _repr_human(self, v: Any) -> str:
        """Render values compactly for human output."""
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, (list, tuple)):
            # Recurse for inner values
            return "[" + ", ".join(self._repr_human(x) for x in v) + "]"
        s = str(v)
        # Quote strings with whitespace
        if any(ch.isspace() for ch in s):
            return f'"{s}"'
        return s

    def _is_changed_from_default(self, dest: str, effective_val: Any) -> bool:
        """
        Compare effective value to the built-in default captured after registration.
        Treat lists/tuples robustly; simple string/number/bool comparisons otherwise.
        """
        if dest not in self._baseline_defaults:
            return True  # if unknown, consider changed (conservative)
        default = self._baseline_defaults[dest]

        def norm(x):
            if isinstance(x, (list, tuple)):
                return list(x)
            return x

        return norm(effective_val) != norm(default)

    def _effective_dict(self, ns_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strip argparse/bookkeeping internals and return only real CLI/config keys.
        """
        exclude = {
            "config", "dump_config", "save_config", "save_format", "force",
        }
        return {k: v for k, v in ns_dict.items() if not k.startswith("_") and k not in exclude}

    def _group_effective(self, eff: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        grouped: Dict[str, Dict[str, Any]] = {}
        assigned: Set[str] = set()
        for sec, dests in self._sections.items():
            block = {k: eff[k] for k in dests if k in eff}
            if block:
                grouped[sec] = block
                assigned |= set(block.keys())
        misc = {k: v for k, v in eff.items() if k not in assigned}
        if misc:
            grouped["misc"] = misc
        return grouped

    def _flat_effective(self, eff: Dict[str, Any]) -> Dict[str, Any]:
        return dict(eff)

    # ---------- internal: JSON -> argparse.defaults ----------
    def _expand_env(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return os.path.expanduser(os.path.expandvars(obj))
        if isinstance(obj, list):
            return [self._expand_env(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self._expand_env(v) for k, v in obj.items()}
        return obj

    def _load_json_config(self, path: str) -> Dict[str, Any]:
        p = pathlib.Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return self._expand_env(data)

    def _scan_actions(self, parser: argparse.ArgumentParser) -> Dict[str, argparse.Action]:
        out: Dict[str, argparse.Action] = {}
        for a in parser._actions:
            d = getattr(a, "dest", None)
            if d and d != "help":
                out[d] = a
        return out

    def _coerce_for_action(self, val: Any, action: argparse.Action) -> Any:
        # booleans (store_true/false)
        if isinstance(action, argparse._StoreTrueAction):
            return bool(val)
        if isinstance(action, argparse._StoreFalseAction):
            return bool(val)

        choices = getattr(action, "choices", None)

        def apply_type(x: Any) -> Any:
            t = getattr(action, "type", None)
            if x is None:
                return None
            return x if t is None else t(x)

        # nargs / append list semantics
        nargs = getattr(action, "nargs", None)
        if nargs in ("*", "+") or isinstance(action, argparse._AppendAction):
            if not isinstance(val, list):
                if isinstance(val, str):
                    items = [s for s in (v.strip() for v in val.split(",")) if s]
                else:
                    items = [val]
            else:
                items = val
            coerced = [apply_type(v) for v in items]
            if choices is not None:
                for v in coerced:
                    if v is None:
                        continue
                    if v not in choices:
                        raise ValueError(f"Invalid value {v!r}; expected one of {sorted(choices)}")
            return coerced

        # count action: allow integer
        if isinstance(action, argparse._CountAction):
            return int(val)

        # scalar
        v = apply_type(val)
        if choices is not None and v is not None and v not in choices:
            raise ValueError(f"Invalid value {v!r}; expected one of {sorted(choices)}")
        return v

    def _apply_config_defaults_from_json(self, parser: argparse.ArgumentParser, cfg: Dict[str, Any]) -> None:
        actions = self._scan_actions(parser)
        # Flatten sectioned or flat JSON
        flat: Dict[str, Any] = {}
        for k, v in cfg.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    flat[kk] = vv
            else:
                flat[k] = v
        # Coerce/validate and set defaults
        defaults: Dict[str, Any] = {}
        for dest, val in flat.items():
            a = actions.get(dest)
            if not a:  # unknown keys -> ignore (or raise if you want strict mode)
                continue
            defaults[dest] = self._coerce_for_action(val, a)
        if defaults:
            parser.set_defaults(**defaults)
# ========================= End ConfigAwareCLI (JSON) ==========================

def main(argv: Optional[List[str]] = None) -> None:

    cli = ConfigAwareCLI(
        description='Bidirectional UDP/TCP multiplexed transfer with keepalive, '
                    'auto-discovery, meters, dashboard, and overlay state machine'
    )

    registrars: List[Tuple[str, Callable[[argparse.ArgumentParser], None]]] = [
        ("stats_board",        StatsBoard.register_cli),
        ("udp_session",        UdpSession.register_cli),
        ("ws_session",         WebSocketSession.register_cli),
        ("tcp_session",        TcpStreamSession.register_cli),
        ("quic_session",       QuicSession.register_cli),
        ("channel_mux",        ChannelMux.register_cli),
        ("admin_web",          AdminWebUI.register_cli),
        ("debug_logging",      DebugLoggingConfigurator.register_cli),
        ("runner",             Runner.register_overlay_cli),
    ]
    args = cli.parse_args(argv, registrars)
    args._config_sections = {k: sorted(v) for k, v in cli.sections.items()}
    args._config_defaults = dict(cli._baseline_defaults)
    args._config_help = dict(cli._action_help)
    args._config_choices = dict(cli._action_choices)

    # Apply logging in one line (behavior unchanged)
    DebugLoggingConfigurator.from_args(args).apply()

    r = Runner(args)
    try:
        asyncio.run(r.run())
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
