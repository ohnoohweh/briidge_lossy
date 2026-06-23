from __future__ import annotations

import errno
import struct
import ipaddress

from ._bridge_import import export_bridge_globals
from .bridge_transport_common import (
    EgressThroughputTracker,
    _bind_family_constraint,
    _family_preference_rank,
    _listener_family_for_host,
    _peer_resolve_mode,
    _resolve_peer_candidates,
    _resolve_cli_peer,
    _split_configured_peer_hosts,
    _strip_brackets,
    _wildcard_host_for_family,
)

_bridge = export_bridge_globals(globals())

_MUX_HDR = struct.Struct(">HHBBH")

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
TRANSMIT_DELAY_EWMA_ALPHA = RTT_EWMA_ALPHA
RETRANS_MULTIPLIER = 1.5
PERSISTENT_MISSING_RETRANS_MULTIPLIER = 1.0
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
        self._last_built_tx_ns: int = 0
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
        self._last_built_tx_ns = tx_ns
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
_bridge_import_debug("bridge_import_before_protocol_singleton")
PROTO = Protocol(BaseFrameV2)
#PROTO = Protocol(BaseFrame)
_bridge_import_debug("bridge_import_after_protocol_singleton", frame_cls="BaseFrameV2")
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


def _monotonic_age_seconds_from_ns(last_rx_wall_ns: Optional[int]) -> Optional[float]:
    try:
        if not last_rx_wall_ns:
            return None
        age_ns = max(0, now_ns() - int(last_rx_wall_ns))
        return age_ns / 1e9
    except Exception:
        return None

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
        allow_ipv4_mapped_send: bool = False,
    ):
        self.udp_transport = udp_transport
        self.log = log
        self.peer_addr: Optional[Tuple[str, int]] = initial_peer
        self._on_bytes_sent = on_bytes_sent
        self._allow_ipv4_mapped_send = bool(allow_ipv4_mapped_send)

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
        send_dst = dst
        if isinstance(dst, tuple) and len(dst) >= 2:
            try:
                sock = self.udp_transport.get_extra_info("socket") if self.udp_transport else None
                family = sock.family if sock is not None else None
                host, port = str(dst[0]), int(dst[1])
                if self._allow_ipv4_mapped_send and family == socket.AF_INET6 and ":" not in host:
                    ipaddress.IPv4Address(host)
                    send_dst = (f"::ffff:{host}", port, 0, 0)
            except Exception:
                send_dst = dst

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(
                "[SENDPORT] send peer_addr=%r len=%d",
                send_dst,
                len(data),
            )

        if send_dst is None:
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug("[PEER/TX] drop %dB: no learned peer yet", len(data))
            return

        try:
            self.udp_transport.sendto(data, send_dst)
            if self._on_bytes_sent:
                self._on_bytes_sent(len(data))
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(
                    "[PEER/TX] %dB -> %s -> %s",
                    len(data),
                    SendPort._pretty(src),
                    SendPort._pretty(send_dst),
                )
        except Exception as e:
            self.log.error("[PEER/TX] send failed: %r", e)
            raise            
# -------------------- Session --------------------
OutgoingSegment = Tuple[int, int, bytes]
QueuedSegment = Tuple[OutgoingSegment, int]
class Session:
    def __init__(self, max_in_flight: int = 32767, proto: Optional[Protocol] = None):
        self.proto = proto or PROTO
        self.next_ctr = 1
        self.send_buf: Dict[int, bytes] = {}
        self.send_meta: Dict[int, OutgoingSegment] = {}
        # Start of the local send path, including queue wait before first emission.
        self.send_path_start_ns: Dict[int, int] = {}
        # First on-wire tx_time_ns stamped into the protocol header on initial emission.
        self.send_txns: Dict[int, int] = {}
        self.last_retx_ns: Dict[int, int] = {}
        self.send_attempts: Dict[int, int] = {}
        self.data_pkt_flags: Dict[int, bool] = {}
        self.peer_reported_missing: Set[int] = set()
        self.stats_hist = {
            "once": 0, "twice": 0, "thrice": 0, "gt3": 0,
            "confirmed_total": 0, "created_total": 0,
        }
        self.max_in_flight = max(1, min(32767, int(max_in_flight)))
        self.wait_queue: Deque[QueuedSegment] = deque()
        self.expected = 1
        self.pending: Dict[int, DataPacket] = {}
        self.missing: Set[int] = set()
        self._pending_highest: Optional[int] = None
        self.reass: Optional[Reassembly] = None
        # RTT mirrors read from Protocol (source of truth)
        self.transmit_delay_sample_ms: float = 0.0
        self.transmit_delay_est_ms: float = 0.0
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
    def _rebuild_data_frame(self, ctr: int, meta: OutgoingSegment) -> bytes:
        frame_type, off_or_len, chunk = meta
        payload = DataPacket.build_payload(ctr, frame_type, off_or_len, chunk)
        return self.proto.build_frame(PTYPE_DATA, payload)

    def _emit_now(self, seg: OutgoingSegment, transport: Any, queued_at_ns: Optional[int] = None) -> None:
        frame_type, off_or_len, chunk = seg
        path_start_ns = int(queued_at_ns or 0)
        ctr = self.reserve_ctr()
        self._record_created_if_appdata(ctr, chunk)
        try:
            frame = self._rebuild_data_frame(ctr, seg)
            tx = int(getattr(self.proto, "_last_built_tx_ns", 0) or 0) or now_ns()
            transport.sendto(frame)
        except Exception:
            self.wait_queue.appendleft((seg, path_start_ns or now_ns()))
            return
        self.send_meta[ctr] = (frame_type, off_or_len, chunk)
        self.send_path_start_ns[ctr] = min(path_start_ns, tx) if path_start_ns > 0 else tx
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
            seg, queued_at_ns = self.wait_queue.popleft()
            self._last_emit_trigger = "flush_queue"
            self._emit_now(seg, transport, queued_at_ns=queued_at_ns)
            emitted += 1
        self._last_emit_trigger = "app_send"
        return emitted
    def _send_or_queue(self, seg: OutgoingSegment, transport: Any) -> None:
        if self.in_flight() < self.max_in_flight:
            self._last_emit_trigger = "app_send"
            self._emit_now(seg, transport)
        else:
            queued_at_ns = now_ns()
            self.wait_queue.append((seg, queued_at_ns))
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

    def _record_transmit_delay_sample_for(self, cnt: int, ack_now_ns: int) -> None:
        path_start_ns = int(self.send_path_start_ns.get(cnt, 0) or 0)
        if path_start_ns <= 0:
            path_start_ns = int(self.send_txns.get(cnt, 0) or 0)
        if path_start_ns <= 0 or ack_now_ns <= path_start_ns:
            return
        elapsed_ms = (ack_now_ns - path_start_ns) / 1e6
        rtt_est_ms = float(getattr(self.proto, "rtt_est_ms", 0.0) or 0.0)
        sample_ms = max(0.0, elapsed_ms - (0.5 * rtt_est_ms if rtt_est_ms > 0.0 else 0.0))
        self.transmit_delay_sample_ms = sample_ms
        if self.transmit_delay_est_ms <= 0.0:
            self.transmit_delay_est_ms = sample_ms
        elif self.transmit_delay_est_ms < sample_ms:
            self.transmit_delay_est_ms = sample_ms
        else:
            self.transmit_delay_est_ms = (
                (1 - TRANSMIT_DELAY_EWMA_ALPHA) * self.transmit_delay_est_ms
                + TRANSMIT_DELAY_EWMA_ALPHA * sample_ms
            )
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(
                "[TXDLY] ctr=%d sample_ms=%.3f est_ms=%.3f elapsed_ms=%.3f rtt_est_ms=%.3f",
                cnt,
                self.transmit_delay_sample_ms,
                self.transmit_delay_est_ms,
                elapsed_ms,
                rtt_est_ms,
            )
    # ------------- ACK/feedback (no timers/retrans scheduling here) -------------
    def confirm_with_feedback(self, last_in_order: int, highest: int, missed: List[int]) -> None:
        if last_in_order == 0 and highest == 0 and len(missed) == 0:
            return
        ack_now_ns = now_ns()
        missed_set = set(missed)
        list_at_capacity = len(missed) >= CONTROL_MAX_MISSED
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(f"[CTL<-] LIO={last_in_order} HI={highest} missed_count={len(missed)} full_list={list_at_capacity}")
        # delete <= last_in_order
        to_del = [cnt for cnt in list(self.send_buf.keys())
                  if ring_cmp(last_in_order, cnt) >= 0]
        for cnt in to_del:
            self._record_transmit_delay_sample_for(cnt, ack_now_ns)
            self._finalize_stats_for(cnt)
            self.send_buf.pop(cnt, None)
            self.send_path_start_ns.pop(cnt, None)
            self.send_txns.pop(cnt, None)
            self.last_retx_ns.pop(cnt, None)
            self.send_meta.pop(cnt, None)
            self.peer_reported_missing.discard(cnt)
        if self.log.isEnabledFor(logging.DEBUG) and to_del:
            self.log.debug(f"[ACK] drop <= LIO: {to_del[:20]}{'…' if len(to_del)>20 else ''}")
        ref = last_in_order if last_in_order != 0 else 1
        if list_at_capacity and missed:
            max_missed = highest_ring(missed, ref)
            upper_bound = max_missed if max_missed is not None else last_in_order
        else:
            upper_bound = highest
        max_span = ahead_distance(upper_bound, ref)
        def in_range(x: int) -> bool:
            d = ahead_distance(x, ref)
            return 0 < d <= max_span
        to_del2 = [cnt for cnt in list(self.send_buf.keys())
                   if in_range(cnt) and cnt not in missed_set and cnt not in self.peer_reported_missing]
        for cnt in to_del2:
            self._record_transmit_delay_sample_for(cnt, ack_now_ns)
            self._finalize_stats_for(cnt)
            self.send_buf.pop(cnt, None)
            self.send_path_start_ns.pop(cnt, None)
            self.send_txns.pop(cnt, None)
            self.last_retx_ns.pop(cnt, None)
            self.send_meta.pop(cnt, None)
            self.peer_reported_missing.discard(cnt)
        if self.log.isEnabledFor(logging.DEBUG) and to_del2:
            self.log.debug(f"[ACK] drop within span(non-missed): {to_del2[:20]}{'…' if len(to_del2)>20 else ''}")
        self.peer_reported_missing.intersection_update(self.send_buf.keys())
        self.peer_reported_missing.update(cnt for cnt in missed_set if cnt in self.send_buf and cnt != 0)
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
    def update_rtt(self, echo_tx_ns: int, *, from_idle: bool = False) -> None:
        before = (self.proto.rtt_sample_ms, self.proto.rtt_est_ms)
        self.proto.on_control_echo(echo_tx_ns)
        rtt_est_ms = float(getattr(self.proto, "rtt_est_ms", 0.0) or 0.0)
        if from_idle and rtt_est_ms > 0.0:
            self.transmit_delay_est_ms = 0.5 * rtt_est_ms
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug(f"[RTT] sample_ms={self.proto.rtt_sample_ms:.3f} est_ms={self.proto.rtt_est_ms:.3f} (prev {before[0]:.3f}/{before[1]:.3f})")
    # ------------- RX side (DATA) -------------
    def identify_missing(self):
        pendingkeylist = [k for k in self.pending.keys() if k != 0]
        self.missing.clear()
        self._pending_highest = None
        if pendingkeylist:
            hi = highest_ring(pendingkeylist, self.expected)
            if hi is not None:
                self._pending_highest = hi
                for m in c16_range(self.expected, hi):
                    if m not in self.pending:
                        self.missing.add(m)
        self._log_missing_state()

    def _log_missing_state(self) -> None:
        if self.log.isEnabledFor(logging.DEBUG):
            try:
                pend = sorted(self.pending.keys())[:12]
                miss = sorted(self.missing)[:12]
                self.log.debug(f"[RX] pending={pend}{'…' if len(self.pending)>12 else ''} missing={miss}{'…' if len(self.missing)>12 else ''} expected={self.expected}")
            except Exception:
                pass

    def _enqueue_out_of_order_packet(self, pkt: DataPacket) -> None:
        ctr = pkt.pkt_counter
        already_pending = ctr in self.pending
        self.pending[ctr] = pkt
        if not already_pending:
            if ctr in self.missing:
                self.missing.discard(ctr)
            else:
                gap_start = self.expected
                if self._pending_highest is not None and ring_cmp(ctr, self._pending_highest) > 0:
                    gap_start = c16_inc(self._pending_highest)
                if self._pending_highest is None or ring_cmp(ctr, self._pending_highest) > 0:
                    for missing_ctr in c16_range(gap_start, ctr):
                        if missing_ctr not in self.pending:
                            self.missing.add(missing_ctr)
                self.missing.discard(ctr)
            if self._pending_highest is None or ring_cmp(ctr, self._pending_highest) > 0:
                self._pending_highest = ctr
        self._log_missing_state()
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
            self._enqueue_out_of_order_packet(pkt)
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
            if self.pending:
                self.identify_missing()
            else:
                self._pending_highest = None
                self.missing.clear()
                self._log_missing_state()
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
        self.send_path_start_ns.clear()
        self.send_txns.clear()
        self.last_retx_ns.clear()
        self.peer_reported_missing.clear()
        self.wait_queue.clear()
        self.send_attempts.clear()
        self.data_pkt_flags.clear()
        self.next_ctr = 1
        self.last_sent_ctr = 0
        self.last_ack_peer = 0
        self.peer_missed_count = 0
        self.last_send_ns = 0
        self.transmit_delay_sample_ms = 0.0
        self.transmit_delay_est_ms = 0.0

    def reset_transport_epoch(self) -> None:
        self.reset_sender()
        self.expected = 1
        self.pending.clear()
        self.missing.clear()
        self._pending_highest = None
        self.reass = None
        self._reass_ctrs.clear()
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
        on_send_error: Optional[Callable[[Exception], None]] = None,
        allow_ipv4_mapped_send: bool = False,
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
        self._on_send_error = on_send_error
        self._allow_ipv4_mapped_send = bool(allow_ipv4_mapped_send)
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
        self._rx_pending: Deque[Tuple[bytes, Any]] = deque()
        self._rx_pending_scheduled = False
        self._completed_pending: Deque[bytes] = deque()
        self._completed_pending_scheduled = False
        self._rx_yield_count = 0
        self._rx_last_yield_gap_ms = 0.0
        self._rx_max_yield_gap_ms = 0.0
        self._completed_yield_count = 0
        self._completed_last_yield_gap_ms = 0.0
        self._completed_max_yield_gap_ms = 0.0

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
            allow_ipv4_mapped_send=self._allow_ipv4_mapped_send,
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

    def reset_transport_epoch_runtime(self) -> None:
        self._last_control_sent_ns = 0
        self._last_sent_last_in_order = 0
        self._established_ns = 0
        self._rx_pending.clear()
        self._rx_pending_scheduled = False
        self._completed_pending.clear()
        self._completed_pending_scheduled = False

    def error_received(self, exc):
        self.session.log.debug("[UDP/PROTO] error_received exc=%r", exc)
        if exc is None or self._on_send_error is None:
            return
        try:
            self._on_send_error(exc)
        except Exception:
            self.session.log.debug("[UDP/PROTO] on_send_error callback failed", exc_info=True)


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
    def _retrans_window_ns(self, multiplier: float) -> int:
        return max(1, int(self.session.rtt_est_ms * 1e6 * float(multiplier)))

    def _retransmit_counters(self, counters: List[int], *, reason: str, window_ns: int, use_first_tx_when_no_retx: bool) -> List[int]:
        if self.send_port is None or not counters:
            return []
        s = self.session
        now = now_ns()
        retx_list: List[int] = []
        seen: Set[int] = set()
        for cnt in counters:
            if cnt == 0 or cnt in seen:
                continue
            seen.add(cnt)
            meta = s.send_meta.get(cnt)
            if meta is None:
                if self.session.log.isEnabledFor(logging.DEBUG):
                    self.session.log.debug("[RTX] skip cnt=%d reason=no_send_meta", cnt)
                continue
            last_retx = s.last_retx_ns.get(cnt, 0)
            first_tx = s.send_txns.get(cnt, 0) if use_first_tx_when_no_retx else 0
            anchor = last_retx or first_tx
            if anchor and (now - anchor) < window_ns:
                continue
            frame = s._rebuild_data_frame(cnt, meta)
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
            self.session.log.debug(
                f"[RTX] {reason} cnts={sorted(retx_list)[:32]}{'…' if len(retx_list)>32 else ''} "
                f"window_ms={window_ns / 1e6:.2f}"
            )
        return retx_list

    def _schedule_retrans(self, missed: List[int]) -> None:
        if self.send_port is None or not missed:
            self.session.peer_missed_count = len(missed)
            return
        s = self.session
        s.peer_missed_count = len(missed)
        self._retransmit_counters(
            missed,
            reason="due_to_control",
            window_ns=self._retrans_window_ns(PERSISTENT_MISSING_RETRANS_MULTIPLIER),
            use_first_tx_when_no_retx=False,
        )

    def _retx_sweep_reported_missing(self) -> None:
        if self.send_port is None:
            return
        s = self.session
        if not s.peer_reported_missing:
            return
        missing_counters = sorted(cnt for cnt in s.peer_reported_missing if cnt in s.send_buf and cnt != 0)
        s.peer_reported_missing.intersection_update(missing_counters)
        self._retransmit_counters(
            missing_counters,
            reason="persistent_missing",
            window_ns=self._retrans_window_ns(PERSISTENT_MISSING_RETRANS_MULTIPLIER),
            use_first_tx_when_no_retx=True,
        )

    def _retx_sweep_unconfirmed(self) -> None:
        if self.send_port is None:
            return
        s = self.session
        if not s.send_buf:
            return
        self._retransmit_counters(
            list(s.send_buf.keys()),
            reason="timeout_sweep",
            window_ns=self._retrans_window_ns(RETRANS_MULTIPLIER),
            use_first_tx_when_no_retx=True,
        )
    # ---- asyncio protocol ----
    def _schedule_rx_pending(self) -> None:
        if self._rx_pending_scheduled:
            return
        self._rx_pending_scheduled = True
        scheduled_at = time.perf_counter()

        def _run() -> None:
            self._rx_pending_scheduled = False
            self._record_yield_gap("_rx", scheduled_at, "myudp_rx_datagram")
            self._process_one_rx_datagram()

        try:
            asyncio.get_running_loop().call_soon(_run)
        except RuntimeError:
            _run()

    def _schedule_completed_pending(self) -> None:
        if self._completed_pending_scheduled:
            return
        self._completed_pending_scheduled = True
        scheduled_at = time.perf_counter()

        def _run() -> None:
            self._completed_pending_scheduled = False
            self._record_yield_gap("_completed", scheduled_at, "myudp_completed_payload")
            self._process_one_completed_payload()

        try:
            asyncio.get_running_loop().call_soon(_run)
        except RuntimeError:
            _run()

    def _record_yield_gap(self, prefix: str, scheduled_at: float, stage: str) -> None:
        gap_ms = max(0.0, (time.perf_counter() - float(scheduled_at)) * 1000.0)
        count_attr = f"{prefix}_yield_count"
        last_attr = f"{prefix}_last_yield_gap_ms"
        max_attr = f"{prefix}_max_yield_gap_ms"
        count = int(getattr(self, count_attr, 0) or 0) + 1
        setattr(self, count_attr, count)
        setattr(self, last_attr, gap_ms)
        setattr(self, max_attr, max(float(getattr(self, max_attr, 0.0) or 0.0), gap_ms))
        if gap_ms >= 20.0 or count <= 3 or (count % 256) == 0:
            self.session.log.info("[UDP/YIELD] stage=%s count=%s gap_ms=%.3f", stage, count, gap_ms)

    def _process_one_completed_payload(self) -> None:
        if not self._completed_pending:
            return
        payload = self._completed_pending.popleft()
        self.on_complete(payload)
        if self._completed_pending:
            self._schedule_completed_pending()

    def _process_one_rx_datagram(self) -> None:
        if not self._rx_pending:
            return
        data, addr = self._rx_pending.popleft()
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
            self.session.update_rtt(echo_ns, from_idle=(kind == "idle"))
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
            if self._rx_pending:
                self._schedule_rx_pending()
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
                self._completed_pending.append(c)
            if self._completed_pending:
                self._schedule_completed_pending()
            if self._rx_pending:
                self._schedule_rx_pending()
            return
        if kind == "control" and pkt:
            cp: ControlPacket = pkt
            self.session.confirm_with_feedback(cp.last_in_order_rx, cp.highest_rx, cp.missed)
            self._schedule_retrans(cp.missed)
            if self.send_port:
                self.session.try_flush_send_queue(self.send_port)
            self._evaluate_control_policy_inbound(False)
        if self._rx_pending:
            self._schedule_rx_pending()

    def datagram_received(self, data: bytes, addr):
        self._rx_pending.append((bytes(data), addr))
        self._schedule_rx_pending()

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
                self._retx_sweep_reported_missing()
                self._retx_sweep_unconfirmed()
        except asyncio.CancelledError:
            return

    # Convenience pass-through for tests
    def send_idle_ping(self, initial=False) -> None:
        self._proto_rt._send_idle_probe(initial)

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        return await self._proto_rt.wait_connected(timeout)

# -----------------------------------------------------------------------------


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
        self._app_payload_passthrough: bool = False
        self._listener_peer_cleanup_task: Optional[asyncio.Task] = None
        self._peer_candidates: List[Tuple[str, int, int]] = []
        self._peer_candidate_index: int = 0
        self._peer_candidate_fallback_task: Optional[asyncio.Task] = None

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
        self._egress_tracker = EgressThroughputTracker()

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
                           help="peer IP/FQDN, or comma-separated IPv4/IPv6 alternatives (IPv6 may be in [brackets])")
        if not _has('--udp-peer-port'):
            p.add_argument('--udp-peer-port', '--peer-port', dest='udp_peer_port', type=int, default=4433, help='peer overlay port')
        if not _has('--udp-peer-resolve-family'):
            p.add_argument(
                '--udp-peer-resolve-family',
                dest='udp_peer_resolve_family',
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
    def set_app_payload_passthrough(self, enabled: bool) -> None:
        self._app_payload_passthrough = bool(enabled)


    def get_metrics(self) -> SessionMetrics:
        if self._listener_mode and self._server_peers:
            try:
                prev_bytes, curr_bytes = self._egress_tracker.snapshot()
                sessions = [ctx["session"] for ctx in self._server_peers.values() if isinstance(ctx, dict) and ctx.get("session") is not None]
                rtt_candidates = [float(getattr(s, "rtt_est_ms", 0.0) or 0.0) for s in sessions if getattr(s, "last_rtt_ok_ns", 0)]
                transmit_delay_sample_candidates = [float(getattr(s, "transmit_delay_sample_ms", 0.0) or 0.0) for s in sessions if float(getattr(s, "transmit_delay_sample_ms", 0.0) or 0.0) > 0.0]
                transmit_delay_est_candidates = [float(getattr(s, "transmit_delay_est_ms", 0.0) or 0.0) for s in sessions if float(getattr(s, "transmit_delay_est_ms", 0.0) or 0.0) > 0.0]
                last_rtt_ok = max((int(getattr(s, "last_rtt_ok_ns", 0) or 0) for s in sessions), default=0)
                return SessionMetrics(
                    rtt_est_ms=max(rtt_candidates) if rtt_candidates else None,
                    transmit_delay_sample_ms=max(transmit_delay_sample_candidates) if transmit_delay_sample_candidates else None,
                    transmit_delay_est_ms=max(transmit_delay_est_candidates) if transmit_delay_est_candidates else None,
                    last_rtt_ok_ns=last_rtt_ok or None,
                    inflight=sum(int(s.in_flight()) for s in sessions if hasattr(s, "in_flight")),
                    max_inflight=sum(int(getattr(s, "max_in_flight", 0) or 0) for s in sessions),
                    waiting_count=sum(int(s.waiting_count()) for s in sessions if hasattr(s, "waiting_count")),
                    egress_prev_window_bytes=prev_bytes,
                    egress_curr_window_bytes=curr_bytes,
                    peer_missed_count=sum(int(getattr(s, "peer_missed_count", 0) or 0) for s in sessions),
                    our_missed_count=sum(len(getattr(s, "missing", [])) for s in sessions if hasattr(s, "missing")),
                )
            except Exception as e:
                self._log.debug("[UdpSession] aggregated get_metrics failed %r", e)
        s = self.inner_session
        try:
            prev_bytes, curr_bytes = self._egress_tracker.snapshot()
            return SessionMetrics(
                rtt_sample_ms     = getattr(s, "rtt_sample_ms", None),
                rtt_est_ms        = getattr(s, "rtt_est_ms", None),
                transmit_delay_sample_ms = (getattr(s, "transmit_delay_sample_ms", None) or None),
                transmit_delay_est_ms = (getattr(s, "transmit_delay_est_ms", None) or None),
                last_rtt_ok_ns    = getattr(s, "last_rtt_ok_ns", None),
                inflight          = int(s.in_flight()) if hasattr(s, "in_flight") else None,
                max_inflight      = getattr(s, "max_in_flight", None),
                waiting_count     = int(s.waiting_count()) if hasattr(s, "waiting_count") else None,
                egress_prev_window_bytes=prev_bytes,
                egress_curr_window_bytes=curr_bytes,
                last_ack_peer     = getattr(s, "last_ack_peer", None),
                last_sent_ctr     = getattr(s, "last_sent_ctr", None),
                expected          = getattr(s, "expected", None),
                peer_missed_count = getattr(s, "peer_missed_count", None),
                our_missed_count  = len(getattr(s, "missing", [])) if hasattr(s, "missing") else None,
            )
        except Exception as e:
            self._log.debug(f"[UdpSession] get_metrics failed on SessionMetrics(..) %r", e)
            return SessionMetrics()

    def get_max_app_payload_size(self) -> int:
        return 65535

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
    def _format_peer_endpoint(host: Optional[object], port: Optional[object]) -> Optional[dict]:
        try:
            if host is None or port is None:
                return None
            host_s = str(host)
            port_i = int(port)
            if not host_s:
                return None
            return {"host": host_s, "port": port_i}
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
                "last_incoming_age_seconds": None,
                "listening": True,
            })
            for peer_id in sorted(self._server_peers.keys()):
                ctx = self._server_peers.get(peer_id, {})
                addr = ctx.get("addr") if isinstance(ctx, dict) else None
                host = addr[0] if isinstance(addr, tuple) and len(addr) >= 2 else None
                port = addr[1] if isinstance(addr, tuple) and len(addr) >= 2 else None
                session = ctx.get("session") if isinstance(ctx, dict) else None
                last_incoming_age_seconds = None
                if isinstance(ctx, dict):
                    last_incoming_age_seconds = _monotonic_age_seconds_from_ns(
                        int(ctx.get("last_incoming_wall_ns") or 0)
                    )
                if last_incoming_age_seconds is None and session is not None:
                    last_incoming_age_seconds = _monotonic_age_seconds_from_ns(
                        int(getattr(getattr(session, "proto", None), "_last_rx_wall_ns", 0) or 0)
                    )
                rows.append({
                    "peer_id": peer_id,
                    "connected": bool(ctx.get("connected")) if isinstance(ctx, dict) else False,
                    "peer": self._format_peer_endpoint(host, port),
                    "mux_chans": sorted(mux_by_peer.get(peer_id, [])),
                    "rtt_est_ms": getattr(session, "rtt_est_ms", None),
                    "last_incoming_age_seconds": last_incoming_age_seconds,
                })
            return rows
        peer_endpoint = None
        with contextlib.suppress(Exception):
            if self._proto is not None and self._proto.send_port is not None:
                peer = getattr(self._proto.send_port, "peer_addr", None)
                if isinstance(peer, tuple) and len(peer) >= 2:
                    peer_endpoint = self._format_peer_endpoint(peer[0], peer[1])
        if not peer_endpoint:
            peer_endpoint = self._format_peer_endpoint(self._peer_host, self._peer_port)
        return [{
            "peer_id": 0,
            "connected": bool(self.is_connected()),
            "peer": peer_endpoint,
            "mux_chans": [],
            "rtt_est_ms": getattr(self.inner_session, "rtt_est_ms", None),
            "last_incoming_age_seconds": _monotonic_age_seconds_from_ns(
                int(getattr(getattr(self.inner_session, "proto", None), "_last_rx_wall_ns", 0) or 0)
            ),
        }]


    # ---- ISession: lifecycle ----
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        listen_host = _strip_brackets(getattr(self._args, "udp_bind", "::"))
        listen_port = int(getattr(self._args, "udp_own_port", 4433))
        self._peer_candidates = self._resolve_configured_peer_candidates(listen_host)
        self._peer_candidate_index = 0
        peer_info = _resolve_cli_peer(
            self._args,
            peer_attr="udp_peer",
            peer_port_attr="udp_peer_port",
            resolve_attr="udp_peer_resolve_family",
            bind_host=listen_host,
            socktype=socket.SOCK_DGRAM,
        )
        peer = None
        peer_family = socket.AF_UNSPEC
        resolve_mode = _peer_resolve_mode(self._args, "udp_peer_resolve_family")
        allow_ipv4_mapped_send = resolve_mode == "ipv6"
        if peer_info is not None:
            peer_host, peer_port, peer_family = peer_info
            peer = (peer_host, peer_port)
            if self._peer_candidates:
                for idx, candidate in enumerate(self._peer_candidates):
                    if candidate == peer_info:
                        self._peer_candidate_index = idx
                        break
        self._listener_mode = peer is None

        if (
            listen_host in ('::', '0.0.0.0')
            and peer_family in (socket.AF_INET, socket.AF_INET6)
        ):
            # If peer family is known (e.g., literal IPv4 peer), avoid AF_UNSPEC
            # endpoint auto-selection that can create an IPv6-only socket and
            # break sendto() to IPv4 peers on some runtimes/platforms.
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
                on_send_error=self._on_peer_send_error,
                allow_ipv4_mapped_send=allow_ipv4_mapped_send,
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
                use_prebuilt_socket = hasattr(socket, "SO_NOSIGPIPE")
                if use_prebuilt_socket:
                    sock_family = family if family != socket.AF_UNSPEC else (
                        socket.AF_INET6 if ":" in listen_host else socket.AF_INET
                    )
                    sock = socket.socket(sock_family, socket.SOCK_DGRAM)
                    sock.setblocking(False)
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
                    except Exception as e:
                        self._log.warning("Could not enable SO_NOSIGPIPE: %r", e)
                    sock.bind(listen)
                    self._log.debug(
                        "[UDP/SESSION] Initiate unconnected Data Endpoint via prebuilt socket "
                        "local=%r initial_peer=%r so_nosigpipe=%s",
                        listen,
                        peer,
                        True,
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
            if self._listener_peer_cleanup_task is None:
                self._listener_peer_cleanup_task = self._loop.create_task(self._listener_peer_cleanup_loop())
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
            if len(self._peer_candidates) > 1 and self._peer_candidate_fallback_task is None:
                self._peer_candidate_fallback_task = self._loop.create_task(self._peer_candidate_fallback_loop())

    async def stop(self) -> None:
        try:
            if self._peer_candidate_fallback_task is not None:
                self._peer_candidate_fallback_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._peer_candidate_fallback_task
                self._peer_candidate_fallback_task = None
            if self._listener_peer_cleanup_task is not None:
                self._listener_peer_cleanup_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._listener_peer_cleanup_task
                self._listener_peer_cleanup_task = None
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
            if self._app_payload_passthrough and peer_id is not None:
                ctx = self._server_peers.get(int(peer_id))
                if not ctx:
                    return 0
                proto = ctx.get("peer_proto")
                session = ctx.get("session")
                if proto is None or session is None or getattr(proto, "send_port", None) is None:
                    return 0
                sent = session.send_application_payload(payload, proto.send_port)
                if sent > 0:
                    self._egress_tracker.record(int(sent))
                return sent
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
            sent = session.send_application_payload(routed_payload, proto.send_port)
            if sent > 0:
                self._egress_tracker.record(int(sent))
            return sent
        if not self._proto or not self._proto.send_port:
            return 0
        sent = self.inner_session.send_application_payload(payload, self._proto.send_port)
        if sent > 0:
            self._egress_tracker.record(int(sent))
        return sent

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
                rewritten = datagram if self._app_payload_passthrough else self._server_rewrite_inbound_app(peer_id, datagram)
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

    def _resolve_configured_peer_candidates(self, bind_host: str) -> List[Tuple[str, int, int]]:
        raw_peer = getattr(self._args, "udp_peer", None)
        if not raw_peer:
            return []
        configured_hosts = _split_configured_peer_hosts(str(raw_peer))
        if len(configured_hosts) <= 1:
            peer_info = _resolve_cli_peer(
                self._args,
                peer_attr="udp_peer",
                peer_port_attr="udp_peer_port",
                resolve_attr="udp_peer_resolve_family",
                bind_host=bind_host,
                socktype=socket.SOCK_DGRAM,
            )
            return [peer_info] if peer_info is not None else []
        resolve_mode = _peer_resolve_mode(self._args, "udp_peer_resolve_family")
        peer_port = int(getattr(self._args, "udp_peer_port", 4433) or 4433)
        candidates: List[Tuple[str, int, int]] = []
        for candidate_host in configured_hosts:
            try:
                candidates.extend(
                    _resolve_peer_candidates(
                        candidate_host,
                        peer_port,
                        resolve_mode=resolve_mode,
                        socktype=socket.SOCK_DGRAM,
                        strict_family=False,
                    )
                )
            except RuntimeError:
                continue
        deduped: List[Tuple[str, int, int]] = []
        for candidate in candidates:
            if candidate not in deduped:
                deduped.append(candidate)
        deduped.sort(key=lambda item: _family_preference_rank(item[2], resolve_mode))
        bind_family = _bind_family_constraint(bind_host)
        if bind_family is not None:
            matching = [item for item in deduped if item[2] == bind_family]
            if matching:
                deduped = matching
        return deduped

    def _rotate_to_next_peer_candidate(self) -> bool:
        if self._listener_mode or self._proto is None or self._proto.send_port is None:
            return False
        next_index = self._peer_candidate_index + 1
        if next_index >= len(self._peer_candidates):
            return False
        old_peer = self._peer_candidates[self._peer_candidate_index]
        new_peer = self._peer_candidates[next_index]
        self._peer_candidate_index = next_index
        self._log.warning(
            "[UDP/SESSION] no liveness on preferred peer %r, falling back to %r",
            old_peer[:2],
            new_peer[:2],
        )
        self.inner_session.reset_transport_epoch()
        with contextlib.suppress(Exception):
            self._proto_state.rtt_est_ms = 0.0
            self._proto_state.rtt_sample_ms = 0.0
            self._proto_state.last_rtt_ok_ns = 0
            self._proto_state._last_rx_tx_ns = 0
            self._proto_state._last_rx_wall_ns = 0
        host, port, _family = new_peer
        self._on_peer_set(host, port)
        self._proto.send_port.set_peer((host, port))
        with contextlib.suppress(Exception):
            self._proto._proto_rt._conn_evt.clear()
            self._proto._proto_rt._conn_state = False
            self._proto._proto_rt._next_probe_due_ns = 0
            self._proto._proto_rt._send_idle_probe(initial=True)
        return True

    def _on_peer_send_error(self, exc: Exception) -> None:
        err = getattr(exc, "errno", None)
        if err not in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL}:
            return
        if self._listener_mode or len(self._peer_candidates) <= 1:
            return
        current = None
        if self._proto is not None and getattr(self._proto, "send_port", None) is not None:
            current = self._proto.send_port.peer_addr
        self._log.warning(
            "[UDP/SESSION] peer send error err=%r current_peer=%r attempting immediate fallback",
            err,
            current,
        )
        self._rotate_to_next_peer_candidate()

    async def _peer_candidate_fallback_loop(self) -> None:
        try:
            while not self._listener_mode and self._peer_candidate_index < (len(self._peer_candidates) - 1):
                await asyncio.sleep(3.0)
                if self.is_connected():
                    return
                if getattr(self._proto_state, "last_rtt_ok_ns", 0):
                    return
                if not self._rotate_to_next_peer_candidate():
                    return
        except asyncio.CancelledError:
            return

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
        rx_wall_ns = now_ns()
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
                allow_ipv4_mapped_send=False,
            )
            self._server_peers[peer_id] = {
                "peer_id": peer_id,
                "addr": key,
                "session": session,
                "peer_proto": peer_proto,
                "connected": False,
                "last_incoming_wall_ns": rx_wall_ns,
            }
            self._server_peer_by_addr[key] = peer_id
            self.peer_proto = peer_proto
            if self._transport is not None:
                peer_proto.connection_made(self._transport)
            self._log.info("[UDP/SESSION] listener accepted peer_id=%s peer=%s", peer_id, key)
            self._on_peer_set_for_peer(peer_id, host, port)
        ctx = self._server_peers.get(peer_id)
        if isinstance(ctx, dict):
            ctx["last_incoming_wall_ns"] = rx_wall_ns
        peer_proto = ctx.get("peer_proto") if isinstance(ctx, dict) else None
        if peer_proto is not None:
            peer_proto.datagram_received(data, key)

    @staticmethod
    def _listener_peer_stale_after_ns(ctx: dict) -> int:
        session = ctx.get("session") if isinstance(ctx, dict) else None
        proto = getattr(session, "proto", None)
        try:
            return max(1, int(getattr(proto, "connected_loss_ns", int(20 * 1e9)) or int(20 * 1e9)))
        except Exception:
            return int(20 * 1e9)

    @staticmethod
    def _listener_peer_last_incoming_wall_ns(ctx: dict) -> int:
        try:
            explicit = int(ctx.get("last_incoming_wall_ns") or 0)
            if explicit > 0:
                return explicit
        except Exception:
            pass
        session = ctx.get("session") if isinstance(ctx, dict) else None
        proto = getattr(session, "proto", None)
        try:
            return int(getattr(proto, "_last_rx_wall_ns", 0) or 0)
        except Exception:
            return 0

    async def _listener_peer_cleanup_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(1.0)
                stale_peer_ids: list[int] = []
                now_v = now_ns()
                for peer_id, ctx in list(self._server_peers.items()):
                    if not isinstance(ctx, dict):
                        continue
                    if bool(ctx.get("connected")):
                        continue
                    last_rx_wall_ns = self._listener_peer_last_incoming_wall_ns(ctx)
                    if last_rx_wall_ns <= 0:
                        continue
                    if (now_v - last_rx_wall_ns) < self._listener_peer_stale_after_ns(ctx):
                        continue
                    stale_peer_ids.append(int(peer_id))
                for peer_id in stale_peer_ids:
                    self._log.info("[UDP/SESSION] dropping stale never-connected listener peer_id=%s", peer_id)
                    await self._close_server_peer(peer_id)
        except asyncio.CancelledError:
            return

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
        hdr = _MUX_HDR
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
        hdr = _MUX_HDR
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
        hdr = _MUX_HDR
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

    def reset_sender(self) -> None:
        # Runner calls this on transport disconnect so reconnect starts from a fresh
        # reliability window (ctr=1) instead of carrying stale counters across epochs.
        with contextlib.suppress(Exception):
            self.inner_session.reset_sender()
        for ctx in self._server_peers.values():
            if not isinstance(ctx, dict):
                continue
            sess = ctx.get("session")
            if sess is None:
                continue
            with contextlib.suppress(Exception):
                sess.reset_sender()

    def reset_transport_epoch(self) -> None:
        # Transport reconnects must start with a fresh reliability epoch in both
        # directions so stale missing/pending feedback cannot leak into the new session.
        with contextlib.suppress(Exception):
            self.inner_session.reset_transport_epoch()
        with contextlib.suppress(Exception):
            if self._proto is not None:
                self._proto.reset_transport_epoch_runtime()
        for ctx in self._server_peers.values():
            if not isinstance(ctx, dict):
                continue
            sess = ctx.get("session")
            if sess is None:
                continue
            with contextlib.suppress(Exception):
                sess.reset_transport_epoch()
            pp = ctx.get("peer_proto")
            if pp is None:
                continue
            with contextlib.suppress(Exception):
                pp.reset_transport_epoch_runtime()

# -----------------------------------------------------------------------------

# ======== Common RTT over stream transports (TCP / WebSocket / QUIC) ========
import struct
import time
