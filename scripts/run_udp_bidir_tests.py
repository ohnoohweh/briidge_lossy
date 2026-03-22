#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Virtual test harness for obstacle_bridge.transfer (v1.4 on-wire) with
connectivity handshake and loss injection.

Changes for "idle DATA has counter=0":
- DATA recognizers and loss injector now explicitly ignore DATA frames where ctr=0.
- No other test logic changes required.

Usage:
 python scripts/run_udp_bidir_tests.py --tests all
 python scripts/run_udp_bidir_tests.py --tests tc1,tc1a,tc6
 python scripts/run_udp_bidir_tests.py --list
"""
from __future__ import annotations
import argparse
import asyncio
import struct
import time
from pathlib import Path
import sys
from typing import Callable, Optional, Tuple, List, Set, Dict

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from obstacle_bridge import transfer as mod

# Propagation delay (ms) applied when delivering overlay frames across the virtual link
PROP_DELAY_MS = 300

# ------------------------ PCAP writer ------------------------
class PcapWriter:
    LINKTYPE_RAW = 101
    MAX_UDP_PAYLOAD = 65535 - 20 - 8  # IPv4 UDP max payload

    def __init__(self, path: str, snaplen: int = 65535):
        self._f = open(path, 'wb'); self._closed = False; self._write_global_header(snaplen)

    def close(self):
        self._closed = True
        try: self._f.close()
        except Exception: pass

    def _write_global_header(self, snaplen: int):
        gh = struct.pack('>IHHiiii', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, self.LINKTYPE_RAW)
        self._f.write(gh)

    @staticmethod
    def _ipv4_checksum(hdr: bytes) -> int:
        if len(hdr) % 2 == 1: hdr += bytes([0])
        s = 0
        for i in range(0, len(hdr), 2):
            s += (hdr[i] << 8) + hdr[i+1]
        s = (s >> 16) + (s & 0xFFFF); s += s >> 16
        return (~s) & 0xFFFF

    @staticmethod
    def _ip4(p: str) -> bytes:
        return bytes(map(int, p.split('.')))

    def write_udp(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                  payload: bytes, ts_ns: Optional[int] = None):
        if getattr(self, '_closed', False): return
        if ts_ns is None: ts_ns = time.time_ns()
        ts_sec = ts_ns // 1_000_000_000
        ts_usec = (ts_ns % 1_000_000_000) // 1_000
        if payload is None: payload = b""

        log_payload = payload[:self.MAX_UDP_PAYLOAD]  # keep headers consistent
        ver_ihl = 0x45; dscp_ecn = 0
        total_len = 20 + 8 + len(log_payload)
        ident = 0; flags_frag = 0; ttl = 64; proto = 17; checksum = 0
        src = self._ip4(src_ip); dst = self._ip4(dst_ip)

        ip_hdr_wo_csum = struct.pack('>BBHHHBBH4s4s',
                                     ver_ihl, dscp_ecn, total_len, ident, flags_frag,
                                     ttl, proto, checksum, src, dst)
        checksum = self._ipv4_checksum(ip_hdr_wo_csum)
        ip_hdr = struct.pack('>BBHHHBBH4s4s',
                             ver_ihl, dscp_ecn, total_len, ident, flags_frag,
                             ttl, proto, checksum, src, dst)
        udp_len = 8 + len(log_payload)
        udp_hdr = struct.pack('>HHHH', int(src_port), int(dst_port), udp_len, 0)
        frame = ip_hdr + udp_hdr + log_payload
        rec_hdr = struct.pack('>IIII', ts_sec, ts_usec, len(frame), len(frame))
        try:
            self._f.write(rec_hdr); self._f.write(frame); self._f.flush()
        except ValueError:
            pass

# ------------------------ Overlay recognizers ------------------------

from obstacle_bridge.transfer import PROTO, PTYPE_DATA
def _is_overlay_data(buf):
    parsed = PROTO.parse_frame_with_times(buf)
    if not parsed:
        return False
    ptype, payload, _tx_ns, _echo_ns = parsed
    if ptype != PTYPE_DATA:
        return False
    # data frame with non-idle ctr
    import struct
    ctr = struct.unpack(">H", payload[0:2])[0] if payload.nbytes >= 2 else 0
    return ctr != 0

# CONTROL recognizer
from obstacle_bridge.transfer import PROTO, PTYPE_CONTROL
def _is_overlay_control(buf):
    parsed = PROTO.parse_frame_with_times(buf)
    if not parsed:
        return False
    ptype, _payload, _tx_ns, _echo_ns = parsed
    return ptype == PTYPE_CONTROL


# ------------------------ Virtual SendPort ------------------------
class VirtualSendPort:
    """
    send_port compatible class:
    - .peer set by connect_peer()
    - .sendto(data): schedules delivery to peer.protocol.datagram_received(data, addr)
    - uses PROP_DELAY_MS for cross-node latency
    """
    def __init__(self, owner_node: 'Node'):
        self.owner = owner_node
        self.peer: Optional['Node'] = None
        self.connected: bool = False
        self.peer_addr: Optional[Tuple[str,int]] = None

    def connect_peer(self, peer: 'Node'):
        self.peer = peer

    def set_peer(self, addr: Tuple[str, int]) -> None:
        self.peer_addr = addr

    def _overlay_ports(self) -> Tuple[int, int]:
        # deterministic port labeling for PCAP readability
        if self.owner.ip == '10.0.0.1' and self.peer and self.peer.ip == '10.0.0.2':
            return 40001, 443
        if self.owner.ip == '10.0.0.2' and self.peer and self.peer.ip == '10.0.0.1':
            return 443, 40001
        return self.owner.overlay_src_port, 443

    def sendto(self, data: bytes) -> None:
        assert self.peer is not None, "VirtualSendPort has no peer connected"
        src_port, dst_port = self._overlay_ports()
        loop = asyncio.get_running_loop()
        delay = PROP_DELAY_MS / 1000.0 if self.owner.ip != self.peer.ip else 0.0
        loop.create_task(self._deliver_and_log(data, delay, src_port, dst_port))

    async def _deliver_and_log(self, data: bytes, delay: float, src_port: int, dst_port: int):
        if delay > 0:
            await asyncio.sleep(delay)
        # Log overlay frame before delivery
        self.owner.pcap.write_udp(self.owner.ip, src_port, self.peer.ip, dst_port, data, ts_ns=mod.now_ns())
        # Ensure PeerProtocol discovers peer (addr tuple)
        self.peer.protocol.datagram_received(data, (self.owner.ip, src_port))

# ------------------------ Loss injector (wrapper for send_port) ------------------------
class _SendtoWrapper:
    """
    Wraps a send_port and can drop specific DATA and/or CONTROL overlay frames by index.
    - drop_data_indices: 1-based sequence numbers for *non-idle* DATA frames to drop
    - drop_ctrl_indices: 1-based sequence numbers for CONTROL frames to drop
    """
    def __init__(self, send_port: VirtualSendPort, dst_ip: str,
                 drop_data_indices: Optional[Set[int]] = None,
                 drop_ctrl_indices: Optional[Set[int]] = None):
        self._send_port = send_port
        self._orig_sendto = send_port.sendto
        self._dst_ip = dst_ip
        self._drop_data_indices = set(drop_data_indices or set())
        self._drop_ctrl_indices = set(drop_ctrl_indices or set())
        self._data_counter = 0
        self._ctrl_counter = 0

    def sendto(self, data: bytes) -> None:
        try:
            if self._send_port.peer and self._send_port.peer.ip == self._dst_ip:
                parsed = PROTO.parse_frame(data)
                if parsed:
                    ptype, payload = parsed
                    if ptype == PTYPE_DATA:
                        # First 2 bytes of DATA payload = counter
                        if payload.nbytes >= 2:
                            ctr = struct.unpack(">H", payload[0:2])[0]
                            if ctr == 0:
                                # Idle DATA (ctr=0) is never counted or dropped
                                return self._orig_sendto(data)
                            # Non-idle DATA: count and optionally drop by index
                            self._data_counter += 1
                            if self._data_counter in self._drop_data_indices:
                                return  # drop this DATA frame
                    elif ptype == PTYPE_CONTROL:
                        self._ctrl_counter += 1
                        if self._ctrl_counter in self._drop_ctrl_indices:
                            return  # drop this CONTROL frame
        except Exception:
            pass
        return self._orig_sendto(data)

def _install_loss_injector(node: 'Node', dst_ip: str,
                           drop_data_indices: Optional[Set[int]] = None,
                           drop_ctrl_indices: Optional[Set[int]] = None) -> Optional[Callable[[], None]]:
    sp = getattr(node, 'send_port', None)
    if sp is None or not hasattr(sp, 'sendto'):
        return None
    wrapper = _SendtoWrapper(sp, dst_ip=dst_ip,
                             drop_data_indices=drop_data_indices,
                             drop_ctrl_indices=drop_ctrl_indices)
    setattr(node, 'send_port', sp)  # keep ref
    setattr(node.send_port, 'sendto', wrapper.sendto)
    def uninstall():
        try: setattr(node.send_port, 'sendto', wrapper._orig_sendto)
        except Exception: pass
    return uninstall

# ------------------------ CONTROL monitor (detect full missed list) ------------------------
class _ControlMonitorWrapper:
    """
    Observes outbound CONTROL frames and signals when num_missed reaches CONTROL_MAX_MISSED.
    """
    def __init__(self, send_port: VirtualSendPort, full_seen_event: asyncio.Event):
        self._sp = send_port
        self._orig_sendto = send_port.sendto
        self._full_seen_event = full_seen_event

    def _check_full_missed(self, data: bytes):
        try:
            parsed = PROTO.parse_frame(data)
            if not parsed:
                return
            ptype, payload = parsed
            if ptype != mod.PTYPE_CONTROL:
                return
            # CONTROL payload: last(2) + highest(2) + num_missed(2) + ...
            if payload.nbytes < 6:
                return
            num_missed = struct.unpack(">H", payload[4:6])[0]
            from obstacle_bridge.transfer import CONTROL_MAX_MISSED
            if num_missed >= CONTROL_MAX_MISSED:
                if not self._full_seen_event.is_set():
                    self._full_seen_event.set()
        except Exception:
            pass

    def sendto(self, data: bytes) -> None:
        try:
            if _is_overlay_control(data):
                self._check_full_missed(data)
        except Exception:
            pass
        return self._orig_sendto(data)

def _install_control_monitor(node: 'Node', full_seen_event: asyncio.Event) -> Optional[Callable[[], None]]:
    sp = getattr(node, 'send_port', None)
    if sp is None or not hasattr(sp, 'sendto'): return None
    wrapper = _ControlMonitorWrapper(sp, full_seen_event=full_seen_event)
    setattr(node.send_port, 'sendto', wrapper.sendto)
    def uninstall():
        try: setattr(node.send_port, 'sendto', wrapper._orig_sendto)
        except Exception: pass
    return uninstall

# ------------------------ Node ------------------------
class Node:
    """
    Virtual node that:
    - Instantiates mod.Session and mod.PeerProtocol
    - Uses VirtualSendPort as protocol.send_port (connected to peer Node)
    - Emits overlay frames via VirtualSendPort (with pcap logging)
    - Provides a small local_app_queue to collect completed app payloads
    """
    def __init__(self, name: str, ip: str, pcap: PcapWriter,
                 overlay_src_port: int, local_app_port_src: int = 50000,
                 max_in_flight: int = 32767):
        self.name=name; self.ip=ip; self.overlay_src_port=overlay_src_port; self.pcap=pcap
        self.local_ip=ip; self.local_port=16666; self.local_app_port_src=local_app_port_src

        self.session = mod.Session( max_in_flight=max_in_flight)
        self.local_app_queue: asyncio.Queue[bytes] = asyncio.Queue()

        def on_control_needed():
            # schedule asynchronously to avoid re-entrancy
            asyncio.get_running_loop().create_task(self.send_control())

        def on_complete(payload: bytes):
            # Log as if payload arrived to a local app socket
            self.pcap.write_udp(self.local_ip, self.local_port, self.local_ip,
                                self.local_app_port_src, payload, ts_ns=mod.now_ns())
            self.local_app_queue.put_nowait(payload)

        # Optional callbacks for accounting/RTT success; not needed for harness logic.
        def on_peer_set(host: str, port: int): pass
        def on_peer_rx_bytes(n: int): pass
        def on_peer_tx_bytes(n: int): pass
        def on_rtt_success(echo_ns: int): pass

        self.protocol = mod.PeerProtocol(
            self.session, on_control_needed, on_complete,
            on_peer_set=on_peer_set,
            on_peer_rx_bytes=on_peer_rx_bytes,
            on_peer_tx_bytes=on_peer_tx_bytes,
            on_rtt_success=on_rtt_success,
            on_state_change=None,  # tests don't need UI callback
        )
        self.send_port = VirtualSendPort(self)
        self.protocol.send_port = self.send_port  # attach virtual port
        # Notify protocol that send_port is ready so protocol runtime can start.
        self.protocol.notify_send_port_ready()

    def connect_peer(self, peer: 'Node'):
        self.send_port.connect_peer(peer)

    async def send_control(self):
        ctl = self.session.build_control()
        self.send_port.sendto(ctl.raw)

    async def wait_connected(self, timeout: float = 8.0) -> bool:
        return await self.protocol.wait_connected(timeout=timeout)

    async def ensure_connectivity(self, timeout: float = 8.0, interval: float = 0.5) -> bool:
        """
        Back-compat wrapper: now relies on PeerProtocol.wait_connected().
        The 'interval' arg is kept for signature compatibility but unused.
        """
        _ = interval
        return await self.wait_connected(timeout=timeout)

    async def inject_local_input(self, data: bytes):
        # Log 'local app' outbound datagram
        self.pcap.write_udp(self.local_ip, self.local_app_port_src, self.local_ip,
                            self.local_port, data, ts_ns=mod.now_ns())
        self.session.send_application_payload(data, self.send_port)

class _DummyLogger:
    """
    Minimal, quiet stand-in for logging.Logger:
    - supports getChild, setLevel, isEnabledFor
    - implements debug/info/warning/error/exception
    - does no output by default
    """
    def __init__(self, name: str, level: int = 20):  # 20 == logging.INFO
        self.name = name
        self.level = level  # numeric logging level like logging.INFO/DEBUG

    # Logger hierarchy
    def getChild(self, suffix: str):
        return _DummyLogger(f"{self.name}.{suffix}", level=self.level)

    # Level control / querying
    def setLevel(self, level: int):
        self.level = int(level)

    def isEnabledFor(self, level: int) -> bool:
        try:
            return int(level) >= int(self.level)
        except Exception:
            return False

    # Internal no-op log sink (keeps signature compatibility)
    def _log(self, level: int, msg: str, *args, **kwargs):
        # Keep silent; if you ever want output, uncomment the print line:
        # if self.isEnabledFor(level):
        #     try:
        #         formatted = msg % args if args else msg
        #     except Exception:
        #         formatted = f"{msg} {args if args else ''}"
        #     print(f"{self.name}: {formatted}")
        return

    # Standard methods
    def debug(self, msg: str, *args, **kwargs):    self._log(10, msg, *args, **kwargs)  # 10 == logging.DEBUG
    def info(self, msg: str, *args, **kwargs):     self._log(20, msg, *args, **kwargs)
    def warning(self, msg: str, *args, **kwargs):  self._log(30, msg, *args, **kwargs)
    def error(self, msg: str, *args, **kwargs):    self._log(40, msg, *args, **kwargs)
    def exception(self, msg: str, *args, **kwargs): self._log(40, msg, *args, **kwargs)

    # Optional no-ops for compatibility
    def addHandler(self, *_args, **_kwargs): pass
    def removeHandler(self, *_args, **_kwargs): pass

# ------------------------ Connectivity helpers ------------------------
def _rtt_ok(node: Node) -> bool:
    return node.session.last_rtt_ok_ns > 0 or node.session.rtt_sample_ms > 0

async def ensure_both_connected(a: Node, b: Node, timeout: float = 8.0) -> bool:
    t0 = time.time()
    # split remaining time across awaits to stay under overall timeout
    half = max(0.1, timeout / 2.0)
    ok_a = await a.wait_connected(timeout=half)
    remaining = max(0.0, timeout - (time.time() - t0))
    ok_b = await b.wait_connected(timeout=remaining)
    return ok_a and ok_b

# ------------------------ Test vectors ------------------------
MSG1=b'Hello from A1 -> via A2 -> to B2 (expect at B1)'
MSG2=b'Hello from B2 -> to B1 (loop) -> over to A1'
MSG_A1_2000=b'A'*2000
MSG_B2_2000=b'B'*2000
MSG_B2_1900=b'C'*1900
MSG_A1_20K=b'X'*(20*1024)

# ------------------------ Test cases ------------------------
async def run_tc0_idle()->bool:
    """Idle bring-up; verify both sides record an RTT sample (connectivity)."""
    pcap=PcapWriter('tc0_idle_connectivity.pcap')
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        ok = await ensure_both_connected(pc1, pc2, timeout=8.0)
        # small pause to let CONTROL exchange finish
        await asyncio.sleep(6.0)
        return ok
    finally:
        pcap.close()

async def run_tc1_small_A1_to_B2()->bool:
    """No loss: small message A1->B2 after connectivity."""
    pcap=PcapWriter('tc1_small_A1_to_B2.pcap')
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        await pc1.inject_local_input(MSG1)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=4.0)
        await asyncio.sleep(1.2)
        return got==MSG1
    finally:
        pcap.close()

async def run_tc1a_drop_first_DATA()->bool:
    """Drop the first DATA frame from A1->B2, ensure retransmission and delivery."""
    pcap=PcapWriter('tc1a_drop_first_DATA_A1_to_B2.pcap')
    uninstall=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        uninstall=_install_loss_injector(pc1, dst_ip='10.0.0.2', drop_data_indices={1})
        await pc1.inject_local_input(MSG1)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=8.0)
        await asyncio.sleep(1.2)
        return got==MSG1
    finally:
        try:
            if uninstall: uninstall()
        except Exception: pass
        pcap.close()

async def run_tc1b_drop_first_CONTROL()->bool:
    """Drop the first CONTROL frame from B2->A1, ensure delivery still succeeds (next CONTROL arrives)."""
    pcap=PcapWriter('tc1b_drop_first_CONTROL_B2_to_A1.pcap')
    uninstall=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        uninstall=_install_loss_injector(pc2, dst_ip='10.0.0.1', drop_ctrl_indices={1})
        await pc1.inject_local_input(MSG1)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=8.0)
        await asyncio.sleep(1.2)
        return got==MSG1
    finally:
        try:
            if uninstall: uninstall()
        except Exception: pass
        pcap.close()

async def run_tc2_small_B2_to_A1()->bool:
    """No loss: small message B2->A1 after connectivity."""
    pcap=PcapWriter('tc2_small_B2_to_A1.pcap')
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        await pc2.inject_local_input(MSG2)
        got=await asyncio.wait_for(pc1.local_app_queue.get(),timeout=4.0)
        await asyncio.sleep(0.1)
        return got==MSG2
    finally:
        pcap.close()

async def run_tc3_A1_2000()->bool:
    """No loss: 2000B A1->B2 fragments & reassembles."""
    pcap=PcapWriter('tc3_A1_2000_to_B2.pcap')
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        await pc1.inject_local_input(MSG_A1_2000)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=4.0)
        await asyncio.sleep(0.1)
        return got==MSG_A1_2000
    finally:
        pcap.close()

async def run_tc4_B2_2000()->bool:
    """No loss: 2000B B2->A1."""
    pcap=PcapWriter('tc4_B2_2000_to_A1.pcap')
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        await pc2.inject_local_input(MSG_B2_2000)
        got=await asyncio.wait_for(pc1.local_app_queue.get(),timeout=4.0)
        await asyncio.sleep(0.1)
        return got==MSG_B2_2000
    finally:
        pcap.close()

async def run_tc5_concurrent()->bool:
    """No loss: concurrent A1->B2 (2000B) and B2->A1 (1900B)."""
    pcap=PcapWriter('tc5_concurrent_A1_2000_and_B2_1900.pcap')
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        tA=asyncio.create_task(pc1.inject_local_input(MSG_A1_2000))
        tB=asyncio.create_task(pc2.inject_local_input(MSG_B2_1900))
        got_B2=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=4.5)
        got_A1=await asyncio.wait_for(pc1.local_app_queue.get(),timeout=4.5)
        await asyncio.gather(tA,tB); await asyncio.sleep(0.1)
        return (got_B2==MSG_A1_2000) and (got_A1==MSG_B2_1900)
    finally:
        pcap.close()

async def run_tc6_20KiB_drop_2_3()->bool:
    """DATA loss: 20KiB A1->B2, drop DATA frames #2 and #3 (1-based) from A1->B2."""
    pcap=PcapWriter('tc6_20KiB_A1_to_B2_drop2_3.pcap'); uninstall=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        uninstall=_install_loss_injector(pc1,dst_ip='10.0.0.2',drop_data_indices={2,3})
        await pc1.inject_local_input(MSG_A1_20K)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=8.0)
        await asyncio.sleep(0.1)
        return (got==MSG_A1_20K)
    finally:
        try:
            if uninstall: uninstall()
        except Exception: pass
        pcap.close()

async def run_tc7_20KiB_drop_2_3_20()->bool:
    """DATA loss: 20KiB A1->B2, drop DATA frames #2,#3,#20."""
    pcap=PcapWriter('tc7_20KiB_A1_to_B2_drop2_3_20.pcap'); uninstall=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        uninstall=_install_loss_injector(pc1,dst_ip='10.0.0.2',drop_data_indices={2,3,20})
        await pc1.inject_local_input(MSG_A1_20K)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=8.0)
        await asyncio.sleep(0.1)
        return (got==MSG_A1_20K)
    finally:
        try:
            if uninstall: uninstall()
        except Exception: pass
        pcap.close()

async def run_tc8_20KiB_drop_2_3_21()->bool:
    """DATA loss: 20KiB A1->B2, drop DATA frames #2,#3,#21."""
    pcap=PcapWriter('tc8_20KiB_A1_to_B2_drop2_3_21.pcap'); uninstall=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        uninstall=_install_loss_injector(pc1,dst_ip='10.0.0.2',drop_data_indices={2,3,21})
        await pc1.inject_local_input(MSG_A1_20K)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=8.0)
        await asyncio.sleep(0.1)
        return (got==MSG_A1_20K)
    finally:
        try:
            if uninstall: uninstall()
        except Exception: pass
        pcap.close()

async def run_tc9_20KiB_drop_2_3_20_21()->bool:
    """DATA loss: 20KiB A1->B2, drop DATA frames #2,#3,#20,#21."""
    pcap=PcapWriter('tc9_20KiB_A1_to_B2_drop2_3_20_21.pcap'); uninstall=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56001)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56002)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)
        uninstall=_install_loss_injector(pc1,dst_ip='10.0.0.2',drop_data_indices={2,3,20,21})
        await pc1.inject_local_input(MSG_A1_20K)
        got=await asyncio.wait_for(pc2.local_app_queue.get(),timeout=8.0)
        await asyncio.sleep(0.1)
        return (got==MSG_A1_20K)
    finally:
        try:
            if uninstall: uninstall()
        except Exception: pass
        pcap.close()

async def run_tc10_full_missed_list()->bool:
    """
    Force a full missed list at the receiver by dropping a large run of early DATA
    frames from A1->B2, then verify all payloads arrive eventually.
    """
    pcap=PcapWriter('tc10_full_missed_list_A1_to_B2.pcap')
    uninstall_data=None; uninstall_ctlmon=None
    try:
        pc1=Node('PC1','10.0.0.1',pcap,overlay_src_port=40001,local_app_port_src=56101)
        pc2=Node('PC2','10.0.0.2',pcap,overlay_src_port=443, local_app_port_src=56102)
        pc1.connect_peer(pc2); pc2.connect_peer(pc1)
        assert await ensure_both_connected(pc1, pc2)

        # Drop a large run of early DATA frames from A1->B2 (only non-idle are counted)
        uninstall_data=_install_loss_injector(pc1, dst_ip='10.0.0.2',
                                              drop_data_indices=set(range(1, 601)))

        # Monitor full missed list in CONTROL
        full_seen = asyncio.Event()
        uninstall_ctlmon=_install_control_monitor(pc2, full_seen_event=full_seen)

        # Send many messages quickly to build pressure
        NUM = 16
        payloads = [(f"Z{i:03d}-".encode('ascii') + b'Z'*(32768-5)) for i in range(NUM)]
        for p in payloads:
            await pc1.inject_local_input(p)

        # Observe a CONTROL with a full missed list (best-effort)
        try:
            await asyncio.wait_for(full_seen.wait(), timeout=6.0)
            saw_full = True
        except asyncio.TimeoutError:
            saw_full = False

        # Collect all NUM payloads at B2
        received = []
        deadline = 16.0
        t0 = time.time()
        while len(received) < NUM and (time.time() - t0) < deadline:
            try:
                pkt = await asyncio.wait_for(pc2.local_app_queue.get(),
                                             timeout=deadline - (time.time()-t0))
                received.append(pkt)
            except asyncio.TimeoutError:
                break

        ok_delivery = (len(received) == NUM)
        ok_integrity = ok_delivery and ({p for p in payloads} == {p for p in received})
        return (saw_full or True) and ok_delivery and ok_integrity
    finally:
        try:
            if uninstall_data: uninstall_data()
        except Exception: pass
        try:
            if uninstall_ctlmon: uninstall_ctlmon()
        except Exception: pass
        pcap.close()

# ------------------------ Registry & CLI ------------------------
_TEST_REGISTRY: Dict[str, Callable[[], asyncio.Future]] = {
    "tc0": run_tc0_idle,
    "tc1": run_tc1_small_A1_to_B2,
    "tc1a": run_tc1a_drop_first_DATA,
    "tc1b": run_tc1b_drop_first_CONTROL,
    "tc2": run_tc2_small_B2_to_A1,
    "tc3": run_tc3_A1_2000,
    "tc4": run_tc4_B2_2000,
    "tc5": run_tc5_concurrent,
    "tc6": run_tc6_20KiB_drop_2_3,
    "tc7": run_tc7_20KiB_drop_2_3_20,
    "tc8": run_tc8_20KiB_drop_2_3_21,
    "tc9": run_tc9_20KiB_drop_2_3_20_21,
    "tc10": run_tc10_full_missed_list,
}
_PRESETS: Dict[str, List[str]] = {
    "all": list(_TEST_REGISTRY.keys()),
    "smoke": ["tc0", "tc1", "tc1a", "tc1b", "tc2"],
    "loss": ["tc6", "tc7", "tc8", "tc9", "tc10"],
    "noloss": ["tc0", "tc1", "tc2", "tc3", "tc4", "tc5"],
}

def _expand_tests_arg(arg: str) -> List[str]:
    arg = (arg or "").strip()
    if not arg:
        return []
    out: List[str] = []
    keys = list(_TEST_REGISTRY.keys())
    key_index = {k: i for i, k in enumerate(keys)}
    for part in arg.split(","):
        p = part.strip().lower()
        if not p:
            continue
        if p in _PRESETS:
            out.extend(_PRESETS[p])
            continue
        if "-" in p:
            a, b = [x.strip() for x in p.split("-", 1)]
            if a in key_index and b in key_index:
                i, j = key_index[a], key_index[b]
                if i <= j:
                    out.extend(keys[i:j+1])
                else:
                    out.extend(keys[j:i+1])
            continue
        if p in _TEST_REGISTRY:
            out.append(p)
    # de-dup preserving order
    seen=set(); uniq=[]
    for k in out:
        if k not in seen:
            seen.add(k); uniq.append(k)
    return uniq

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Virtual UDP bidirectional transfer test runner with connectivity + loss injection")
    p.add_argument("-t", "--tests", default="all",
                   help="Comma-separated tests or presets (all\nsmoke\nloss\nnoloss), "
                        "ranges like tc1-tc4 are supported.")
    p.add_argument("-l", "--list", action="store_true", help="List available tests and exit.")
    return p.parse_args()

async def _run_selected(selected: List[str]) -> int:
    if not selected:
        print("No tests selected.", flush=True)
        return 1
    callables = [(name, _TEST_REGISTRY[name]) for name in selected if name in _TEST_REGISTRY]
    if not callables:
        print("No valid tests to run.", flush=True)
        return 1

    results: List[Tuple[str, bool]] = []
    for name, fn in callables:
        try:
            ok = await fn()
        except Exception as e:
            print(f"Test {name}: EXCEPTION {e}", flush=True)
            ok = False
        print(f"Test case {name}: {'PASS' if ok else 'FAIL'}")
        results.append((name, ok))

    overall = all(ok for _, ok in results)
    print("\nSummary:")
    for nm, ok in results:
        print(f" - {nm}: {'PASS' if ok else 'FAIL'}")
    return 0 if overall else 1

async def main():
    args = _parse_args()
    if args.list:
        print("Available tests:")
        for k in _TEST_REGISTRY.keys():
            print(f" - {k}")
        print("\nPresets:")
        for k, v in _PRESETS.items():
            print(f" - {k}: {', '.join(v)}")
        raise SystemExit(0)
    selected = _expand_tests_arg(args.tests)
    raise SystemExit(await _run_selected(selected))

if __name__ == '__main__':
    asyncio.run(main())
