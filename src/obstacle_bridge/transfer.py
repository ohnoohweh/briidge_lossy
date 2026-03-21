#!/usr/bin/env python3
from __future__ import annotations
import asyncio
import logging
import struct
import time
from collections import deque
from typing import Dict, Optional, Tuple, List, Set, Deque, Any, Callable
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
        self._send_fn = send_fn
        # wrap state change to also log transitions
        if on_state_change:
            def _wrapped(state: bool, _cb=on_state_change):
                try:
                    if self._log.isEnabledFor(logging.DEBUG):
                        self._log.debug(f"[STATE] {'CONNECTED' if state else 'DISCONNECTED'}")
                except Exception:
                    pass
                try:
                    _cb(state)
                except Exception:
                    pass
            self._on_state_change = _wrapped
        else:
            self._on_state_change = lambda s: self._log.debug(f"[STATE] {'CONNECTED' if s else 'DISCONNECTED'}") if self._log.isEnabledFor(logging.DEBUG) else None
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
            return
        try:
            frame = self.proto.build_idle_ping(initial)
            self._send_fn(frame)
            if self._log.isEnabledFor(logging.DEBUG):
                self._log.debug(f"[IDLE] tx initial={initial}")
        except Exception:
            pass
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
    def __init__(
        self,
        udp_transport: asyncio.DatagramTransport,
        log: logging.Logger,
        connected: bool = False,
        initial_peer: Optional[Tuple[str, int]] = None,
        prepeer_queue_limit: int = 4096,
        on_bytes_sent: Optional[Callable[[int], None]] = None,
    ):
        self.udp_transport = udp_transport
        self.log = log
        self.connected = connected
        self.peer_addr: Optional[Tuple[str, int]] = initial_peer
        self._prepeer: Deque[bytes] = deque()
        self._prepeer_queue_limit = prepeer_queue_limit
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

    def set_connected(self, connected: bool) -> None:
        self.connected = connected
    def set_peer(self, addr: Tuple[str, int]) -> None:
        if self.peer_addr != addr:
            host, port = addr
            pretty = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
            self.log.info(f"Overlay peer learned: {pretty}")
            self.peer_addr = addr
        while self._prepeer:
            data = self._prepeer.popleft()
            try:
                if self.connected:
                    self.udp_transport.sendto(data)
                else:
                    self.udp_transport.sendto(data, self.peer_addr)
                if self._on_bytes_sent:
                    self._on_bytes_sent(len(data))
            except Exception:
                break

    def sendto(self, data: bytes) -> None:
        if not data:
            return
        dst = None
        try:
            if self.connected:
                # Connected UDP: OS remembers peer; still try to resolve the peername for logs
                dst = self.udp_transport.get_extra_info("peername") if self.udp_transport else None
                self.udp_transport.sendto(data)  # type: ignore
            else:
                # Unconnected UDP: we must have a learned peer
                if self.peer_addr is None:
                    # queue handled by other methods; do nothing here
                    return
                dst = self.peer_addr
                self.udp_transport.sendto(data, self.peer_addr)  # type: ignore
            if self._on_bytes_sent:
                self._on_bytes_sent(len(data))
        finally:
            if self.log.isEnabledFor(logging.DEBUG):
                try:
                    self.log.debug(f"[PEER/TX] {len(data)}B -> {SendPort._pretty(dst)}")
                except Exception:
                    pass
# -------------------- Session --------------------
OutgoingSegment = Tuple[int, int, bytes]
class Session:
    def __init__(self, max_in_flight: int = 32767):
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
        frame = PROTO.build_frame(PTYPE_CONTROL, payload)
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
            frame = PROTO.build_frame(PTYPE_DATA, payload)
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
        return PROTO.rtt_est_ms
    @property
    def rtt_sample_ms(self) -> float:
        return PROTO.rtt_sample_ms
    @property
    def last_rtt_ok_ns(self) -> int:
        return PROTO.last_rtt_ok_ns
    def update_rtt(self, echo_tx_ns: int) -> None:
        before = (PROTO.rtt_sample_ms, PROTO.rtt_est_ms)
        PROTO.on_control_echo(echo_tx_ns)
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(f"[RTT] sample_ms={PROTO.rtt_sample_ms:.3f} est_ms={PROTO.rtt_est_ms:.3f} (prev {before[0]:.3f}/{before[1]:.3f})")
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
        on_peer_set=None,
        on_peer_rx_bytes: Optional[Callable[[int], None]] = None,
        on_peer_tx_bytes: Optional[Callable[[int], None]] = None,
        on_rtt_success: Optional[Callable[[int], None]] = None,
        on_state_change: Optional[Callable[[bool], None]] = None,
    ):
        self.session = session
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
        self._proto_rt = ProtocolRuntime(PROTO, log=self.session.log.getChild("rt"))
        self._runtime_attached = False
        # Timers owned here: control pacing + loss mitigation sweep
        self.controltimerstart()
        self.retxtimerstart()
    @property
    def unidentified_frames(self) -> int:
        return self._unidentified_frames

    def connection_made(self, transport: asyncio.BaseTransport):
        self.udp_transport = transport  # type: ignore
        try:
            peername = self.udp_transport.get_extra_info("peername")
            sockname = self.udp_transport.get_extra_info("sockname")
            self.session.log.info(f"[UDP/SOCK] local={sockname} peer={peername}")
        except Exception:
            pass
        connected = bool(peername)
        self.send_port = SendPort(
            self.udp_transport,
            self.session.log,
            connected=connected,
            on_bytes_sent=self._on_peer_tx_bytes,
        )
        # Attach runtime when send_port is available
        self.notify_send_port_ready()
    def connection_lost(self, exc: Optional[Exception]) -> None:
        try:
            self._proto_rt.detach()
        except Exception:
            pass
        self.controltimerstop()
        self.retxtimerstop()
    def notify_send_port_ready(self) -> None:
        if self.send_port and not self._runtime_attached:
            try:
                self._proto_rt.attach(self.send_port.sendto, self._on_state_change)
                self._runtime_attached = True
            except Exception:
                self._runtime_attached = False

    def _maybe_learn_peer(self, addr):
        if self.send_port is None:   # NOTE: this is the original name in your file; keep it as is
            return
        host, port = str(addr[0]), int(addr[1])
        cur = self.send_port.peer_addr

        # 1) First-time learn: adopt immediately
        if (not self.send_port.connected) and (cur is None):
            self.send_port.set_peer((host, port))
            if callable(self.on_peer_set):
                try:
                    self.on_peer_set(host, port)
                except Exception:
                    pass
            return

        # 2) Peer move: source changed
        if cur and (host, port) != cur:
            # Decide whether to adopt now
            try:
                connected = bool(PROTO.is_connected())
                last_ok = int(PROTO.last_rtt_ok_ns)
            except Exception:
                connected, last_ok = False, 0

            adopt = (not connected) or (now_ns() - (last_ok or 0) >= self._move_grace_ns)

            if adopt:
                if self.session.log.isEnabledFor(logging.INFO):
                    try:
                        age_s = (now_ns() - (last_ok or 0)) / 1e9
                        self.session.log.info(
                            f"[PEER] move adopt old={cur[0]}:{cur[1]} -> new={host}:{port} age_last_rtt={age_s:.1f}s"
                        )
                    except Exception:
                        pass
                self.send_port.set_peer((host, port))
                if callable(self.on_peer_set):
                    try:
                        self.on_peer_set(host, port)
                    except Exception:
                        pass
            else:
                # Optional: DEBUG breadcrumb to show we saw a different sender but chose not to adopt (yet)
                if self.session.log.isEnabledFor(logging.DEBUG):
                    try:
                        self.session.log.debug(
                            f"[PEER] move seen but delayed (still connected, grace {self._move_grace_ns/1e9:.1f}s): "
                            f"current={cur[0]}:{cur[1]} new={host}:{port}"
                        )
                    except Exception:
                        pass
    def _parse_and_count(self, data: bytes):
        parsed = PROTO.parse_frame_with_times(data)
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
        if ptype == PROTO.PTYPE_CONTROL:
            cp = ControlPacket.parse_payload(payload, data)
            if cp is None:
                self._unidentified_frames += 1
                return None, None, 0, 0
            return "control", cp, tx_ns, echo_ns
        if ptype == PROTO.PTYPE_IDLE:
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
                interval = int(0.5 * (PROTO.rtt_est_ms / 1000.0) * 1e9)
                elapsed = (now_t - ref) >= interval if ref else True
                if elapsed:
                    self._emit_control(now_t, reason="advanced_in_order")
                return
        if miss_count > 0:
            interval = int(0.5 * (PROTO.rtt_est_ms / 1000.0) * 1e9)
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
                interval = int(0.5 * (PROTO.rtt_est_ms / 1000.0) * 1e9)
                if ref and (now_t - ref) >= interval:
                    self._emit_control(now_t, reason="timer_paced_clear_miss")
                return
        if miss_count > 0:
            interval = int(0.5 * (PROTO.rtt_est_ms / 1000.0) * 1e9)
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
            frame = PROTO.build_frame(PTYPE_DATA, payload)
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
            frame = PROTO.build_frame(PTYPE_DATA, payload)
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
        # --- NEW: per-datagram RX visibility (DEBUG) ---
        if self.session.log.isEnabledFor(logging.DEBUG):
            try:
                host, port = str(addr[0]), int(addr[1])
                self.session.log.debug(f"[PEER/RX] {len(data)}B <- {host}:{port}")
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
        now_t = now_ns()
        kind, pkt, tx_ns, echo_ns = self._parse_and_count(data)
        PROTO.on_frame_received(tx_ns, now_t)
        if echo_ns:
            self.session.update_rtt(echo_ns)
            if self._established_ns == 0:
                self._established_ns = now_ns()
            if callable(self._on_rtt_success):
                try:
                    self._on_rtt_success(echo_ns)
                except Exception:
                    pass
        if kind == "idle":
            # Reflect only initial idle probes (echo==0)
            if echo_ns == 0:
                try:
                    # reflect WITHOUT initial flag => echo gets filled
                    frame = PROTO.build_frame(PROTO.PTYPE_IDLE, b"", initial=False)
                    self.send_port.sendto(frame)
                except Exception:
                    pass
            if self.session.log.isEnabledFor(logging.DEBUG):
                self.session.log.debug(f"[IDLE] rx echo_ns={echo_ns} -> {'reflect' if echo_ns==0 else 'no-reflect'}")
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
        self._proto_rt.send_idle_ping(initial)
    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        return await self._proto_rt.wait_connected(timeout)
