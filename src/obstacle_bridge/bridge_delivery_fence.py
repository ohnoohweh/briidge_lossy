"""Outer authenticated delivery fence for resumable stream overlays.

The wrapper owns the post-SecureLink RTT signal and the plaintext replay
ledger.  It deliberately retains application bytes, never SecureLink
ciphertext, so a resumed transport sends the retained records through the new
compression/SecureLink epoch.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
import time
from collections import OrderedDict
from typing import Any, Callable, Optional

from .bridge_connection_lifecycle import ConnectionLifecycleEmitter, ConnectionState
from .bridge_transport_common import DeliveryFenceCodec


class DeliveryFenceSession:
    LAYER = "delivery_fence"
    MAX_PENDING_BYTES = 4 * 1024 * 1024
    PING_INTERVAL_S = 0.5
    _MUX_HDR = struct.Struct(">HBHBH")

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._log = logging.getLogger("delivery_fence")
        self._on_app: Optional[Callable[..., None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._on_transport_epoch_change: Optional[Callable[[int], None]] = None
        self._connection_lifecycle = ConnectionLifecycleEmitter()
        self._inner_epoch = 0
        self._started = False
        self._inner_ready = False
        self._connected = False
        self._preserving_lower_epoch = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._next_sequence: dict[int, int] = {}
        self._delivered_sequence: dict[int, int] = {}
        self._confirmed_sequence: dict[int, int] = {}
        self._pending: dict[int, OrderedDict[int, bytes]] = {}
        self._pending_bytes = 0
        # The fence intentionally sits outside ChannelMux.  A stream listener
        # can no longer see a mux header while it routes the fence envelope,
        # so retain the same peer/channel association here and restore the
        # peer's original channel number on egress.
        self._peer_mux_to_local: dict[tuple[int, int], int] = {}
        self._local_mux_to_peer: dict[int, tuple[int, int]] = {}
        self._next_server_mux_chan = 1
        inner.set_on_app_payload(self._on_inner_app)
        inner.set_on_state_change(self._on_inner_state)
        epoch_setter = getattr(inner, "set_on_transport_epoch_change", None)
        if callable(epoch_setter):
            epoch_setter(self._on_inner_transport_epoch_change)
        setter = getattr(inner, "set_on_connection_lifecycle", None)
        if callable(setter):
            setter(self._on_inner_lifecycle)

    def __getattr__(self, name: str):
        """Keep controls and diagnostics of transparent inner layers reachable.

        The delivery fence is intentionally the outermost transport wrapper.
        Operator controls, including SecureLink rekey/reload, are implemented
        by lower layers, so hiding their methods makes a fenced peer appear to
        have SecureLink disabled.
        """
        return getattr(self._inner, name)

    @staticmethod
    def _key(peer_id: Optional[int]) -> int:
        return int(peer_id or 0)

    async def start(self) -> None:
        # The record envelope owns routing and sequence identity above every
        # transform.  Stream listeners must therefore not interpret its first
        # bytes as a ChannelMux header while it crosses the raw transport.
        setter = getattr(self._inner, "set_app_payload_passthrough", None)
        if callable(setter):
            setter(True)
        self._started = True
        await self._inner.start()
        self._heartbeat_task = asyncio.create_task(self._heartbeat())

    async def stop(self) -> None:
        self._started = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None
        await self._inner.stop()

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        if self._connected:
            return True
        deadline = time.monotonic() + float(timeout or 0.0)
        while self._started and (timeout is None or time.monotonic() < deadline):
            if self._connected:
                return True
            await asyncio.sleep(0.02)
        return self._connected

    def is_connected(self) -> bool:
        return bool(self._connected)

    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        if not payload:
            return 0
        payload, peer_id = self._route_outbound_mux(payload, peer_id)
        key = self._key(peer_id)
        sequence = self._next_sequence.get(key, 0) + 1
        frame = DeliveryFenceCodec.encode_data(sequence, payload)
        if self._pending_bytes + len(frame) > self.MAX_PENDING_BYTES:
            return 0
        self._next_sequence[key] = sequence
        self._pending.setdefault(key, OrderedDict())[sequence] = frame
        self._pending_bytes += len(frame)
        if self._inner_ready:
            self._send_inner(frame, peer_id)
        return len(payload)

    def get_max_app_payload_size(self) -> int:
        return max(0, int(self._inner.get_max_app_payload_size()) - DeliveryFenceCodec._HEADER.size)

    def get_stream_record_limit(self) -> int:
        getter = getattr(self._inner, "get_stream_record_limit", None)
        return int(getter()) if callable(getter) else self.get_max_app_payload_size()

    def set_on_app_payload(self, cb: Callable[..., None]) -> None: self._on_app = cb
    def set_on_state_change(self, cb: Callable[[bool], None]) -> None: self._on_state = cb
    def set_on_connection_lifecycle(self, cb: Callable[[Any], None]) -> None:
        self._connection_lifecycle.set_callback(cb)
    def set_on_peer_rx(self, cb: Callable[[int], None]) -> None: self._inner.set_on_peer_rx(cb)
    def set_on_peer_tx(self, cb: Callable[[int], None]) -> None: self._inner.set_on_peer_tx(cb)
    def set_on_peer_set(self, cb: Callable[[str, int], None]) -> None: self._inner.set_on_peer_set(cb)
    def set_on_app_from_peer_bytes(self, cb: Callable[[int], None]) -> None: self._inner.set_on_app_from_peer_bytes(cb)
    def set_on_transport_epoch_change(self, cb: Callable[[int], None]) -> None: self._on_transport_epoch_change = cb
    def request_reconnect(self) -> bool:
        requester = getattr(self._inner, "request_reconnect", None)
        return bool(requester()) if callable(requester) else False
    def request_connection_rotation(self, reason: str = ""): return self._inner.request_connection_rotation(reason)
    def get_metrics(self): return self._inner.get_metrics()
    def get_overlay_peers_snapshot(self): return self._inner.get_overlay_peers_snapshot()
    def retire_server_peer_epoch(self, peer_id: int, *, reason: str = "") -> bool: return self._inner.retire_server_peer_epoch(peer_id, reason=reason)

    def get_connection_layers_snapshot(self) -> list[dict[str, object]]:
        layers = list(self._inner.get_connection_layers_snapshot() or [])
        layers.append({"layer": self.LAYER, "state": "connected" if self._connected else "connecting", "connected": self._connected, "app_ready": self._connected, "pending_bytes": self._pending_bytes})
        return layers

    def get_connection_lifecycle_snapshot(self) -> dict[str, object]:
        return self._connection_lifecycle.snapshot()

    def _send_inner(self, frame: bytes, peer_id: Optional[int]) -> None:
        try:
            self._inner.send_app(frame, peer_id=peer_id)
        except TypeError:
            self._inner.send_app(frame)

    def _on_inner_state(self, connected: bool) -> None:
        self._log.debug("[DELIVERY-FENCE] lower state connected=%s", bool(connected))
        self._inner_ready = bool(connected)
        if connected:
            self._preserving_lower_epoch = False
            self._replay_all()
            self._send_ping_all()
        elif not self._preserving_lower_epoch:
            self._set_connected(False)

    def _on_inner_lifecycle(self, event: Any) -> None:
        # Lifecycle visibility is owned by the outer authenticated fence.
        self._log.debug(
            "[DELIVERY-FENCE] lower lifecycle connected=%s epoch=%s reason=%s",
            bool(getattr(event, "connected", False)),
            getattr(event, "epoch", 0),
            getattr(event, "reason", ""),
        )
        self._inner_epoch = max(self._inner_epoch, int(getattr(event, "epoch", 0) or 0))
        if bool(getattr(event, "connected", False)):
            # SecureLink emits its authenticated lifecycle edge even when the
            # lower socket stayed open across a rekey/reconnect.  Treat that
            # edge as the only safe point to replay plaintext into the fresh
            # protection epoch.
            self._inner_ready = True
            self._preserving_lower_epoch = False
            self._replay_all()
            self._send_ping_all()
        else:
            self._inner_ready = False
            if self._preserving_lower_epoch:
                return
            self._set_connected(False)
            self._connection_lifecycle.transition(
                ConnectionState.DISCONNECTED,
                self._inner_epoch,
                str(getattr(event, "reason", "") or "inner_disconnected"),
            )

    def _on_inner_transport_epoch_change(self, epoch: int) -> None:
        """Fence replay follows a lower replacement without resetting mux streams."""
        self._inner_epoch = max(self._inner_epoch, int(epoch or 0))
        self._inner_ready = False
        self._preserving_lower_epoch = True
        layers = list(getattr(self._inner, "get_connection_layers_snapshot", lambda: [])() or [])
        protected = any(str(layer.get("layer") or "") == "secure_link" for layer in layers if isinstance(layer, dict))
        if not protected and bool(getattr(self._inner, "is_connected", lambda: False)()):
            # Cleartext stream overlays have no security readiness edge to
            # await. The newly installed byte transport is safe to replay on.
            self._inner_ready = True
            self._replay_all()
            self._send_ping_all()
        # ChannelMux only receives transport-epoch resets for hard teardown.
        # A stream transport replacement handled by this fence deliberately
        # preserves its local TCP/UDP service channels.

    def _on_inner_app(self, payload: bytes, peer_id: Optional[int] = None) -> None:
        decoded = DeliveryFenceCodec.decode(payload)
        if decoded is None:
            self._log.debug("[DELIVERY-FENCE] ignored non-fence frame bytes=%d peer_id=%r", len(payload), peer_id)
            return
        kind, sequence, body = decoded
        key = self._key(peer_id)
        if kind == DeliveryFenceCodec.KIND_DATA:
            delivered = self._delivered_sequence.get(key, 0)
            if delivered == 0 and sequence > 1:
                # A listener that has been restarted has no retained receive
                # watermark.  Its peer only discards records after a prior
                # authenticated PONG, so the first post-restart record is a
                # safe new baseline rather than a permanent artificial gap.
                # A live listener never takes this branch: it retains its
                # watermark across a lower-transport epoch.
                delivered = sequence - 1
                self._delivered_sequence[key] = delivered
            if sequence <= delivered:
                self._send_pong(peer_id)
                return
            if sequence != delivered + 1:
                # Reliable stream transports preserve order.  A gap must wait
                # for replay rather than allowing a byte-stream hole through.
                return
            self._delivered_sequence[key] = sequence
            body = self._route_inbound_mux(body, peer_id)
            if callable(self._on_app):
                try:
                    self._on_app(body, peer_id=peer_id)
                except TypeError:
                    self._on_app(body)
            # A DATA record is delivery evidence.  Acknowledge it immediately
            # rather than retaining plaintext until the next periodic probe.
            self._send_pong(peer_id)
            return
        if kind == DeliveryFenceCodec.KIND_PING:
            self._log.debug("[DELIVERY-FENCE] ping peer_id=%r", peer_id)
            self._send_pong(peer_id, echo_tx_ns=DeliveryFenceCodec.decode_ping(body)[0])
            # Receiving a protected fence probe is itself evidence that this
            # peer can deliver into the current epoch.  Passive listeners do
            # not initiate a probe before a peer is known, so their matching
            # readiness edge is established here.
            self._set_connected(True)
            return
        _echo, delivered = DeliveryFenceCodec.decode_pong(body)
        self._log.debug("[DELIVERY-FENCE] pong peer_id=%r delivered=%d", peer_id, delivered)
        self._confirm(key, delivered)
        self._preserving_lower_epoch = False
        self._set_connected(True)

    @classmethod
    def _replace_mux_channel(cls, payload: bytes, channel_id: int) -> bytes:
        if len(payload) < cls._MUX_HDR.size:
            return payload
        try:
            _old, proto, counter, mtype, data_length = cls._MUX_HDR.unpack(payload[:cls._MUX_HDR.size])
        except struct.error:
            return payload
        if len(payload) != cls._MUX_HDR.size + data_length:
            return payload
        return cls._MUX_HDR.pack(channel_id, proto, counter, mtype, data_length) + payload[cls._MUX_HDR.size:]

    def _allocate_server_mux_channel(self) -> int:
        channel_id = self._next_server_mux_chan
        while channel_id in self._local_mux_to_peer:
            channel_id = 1 if channel_id >= 0xFFFF else channel_id + 2
        self._next_server_mux_chan = 1 if channel_id >= 0xFFFF else channel_id + 2
        return channel_id

    def _route_inbound_mux(self, payload: bytes, peer_id: Optional[int]) -> bytes:
        """Give each listener peer an unambiguous local ChannelMux channel."""
        if peer_id is None or len(payload) < self._MUX_HDR.size:
            return payload
        try:
            peer_channel, _proto, _counter, _mtype, data_length = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        except struct.error:
            return payload
        if len(payload) != self._MUX_HDR.size + data_length:
            return payload
        mapping_key = (int(peer_id), int(peer_channel))
        local_channel = self._peer_mux_to_local.get(mapping_key)
        if local_channel is None:
            local_channel = int(peer_channel)
            if local_channel in self._local_mux_to_peer:
                local_channel = self._allocate_server_mux_channel()
            self._peer_mux_to_local[mapping_key] = local_channel
            self._local_mux_to_peer[local_channel] = mapping_key
        return self._replace_mux_channel(payload, local_channel)

    def _route_outbound_mux(self, payload: bytes, peer_id: Optional[int]) -> tuple[bytes, Optional[int]]:
        """Recover the listener peer and its channel number before fencing."""
        if len(payload) < self._MUX_HDR.size:
            return payload, peer_id
        try:
            local_channel, _proto, _counter, _mtype, data_length = self._MUX_HDR.unpack(payload[:self._MUX_HDR.size])
        except struct.error:
            return payload, peer_id
        if len(payload) != self._MUX_HDR.size + data_length:
            return payload, peer_id
        mapping = self._local_mux_to_peer.get(int(local_channel))
        if mapping is None:
            return payload, peer_id
        mapped_peer, peer_channel = mapping
        if peer_id is None:
            peer_id = mapped_peer
        if int(peer_id) == mapped_peer:
            payload = self._replace_mux_channel(payload, peer_channel)
        return payload, peer_id

    def _confirm(self, key: int, delivered: int) -> None:
        if delivered <= self._confirmed_sequence.get(key, 0):
            return
        self._confirmed_sequence[key] = delivered
        pending = self._pending.get(key)
        while pending:
            sequence, frame = next(iter(pending.items()))
            if sequence > delivered:
                break
            pending.popitem(last=False)
            self._pending_bytes -= len(frame)

    def _replay_all(self) -> None:
        for key, pending in self._pending.items():
            for frame in pending.values():
                self._send_inner(frame, key or None)

    def _send_ping_all(self) -> None:
        keys = set(self._pending) | set(self._delivered_sequence)
        # A listener has no fence state for a just-admitted peer yet.  Send
        # its first probe to that concrete peer rather than peer_id=None:
        # lower stream listeners reserve the unscoped route for ChannelMux
        # rewriting, which would otherwise interpret OBRT bytes as a mux
        # header and truncate the probe.
        if not keys:
            getter = getattr(self._inner, "get_overlay_peers_snapshot", None)
            if callable(getter):
                try:
                    for row in list(getter() or []):
                        if not isinstance(row, dict) or bool(row.get("listening")):
                            continue
                        peer_id = row.get("peer_id")
                        if peer_id is not None:
                            keys.add(int(peer_id))
                except Exception:
                    pass
        if not keys:
            keys.add(0)
        now_ns = time.monotonic_ns()
        for key in keys:
            self._log.debug("[DELIVERY-FENCE] ping send peer_id=%r delivered=%d", key or None, self._delivered_sequence.get(key, 0))
            self._send_inner(DeliveryFenceCodec.encode_ping(now_ns, 0, self._delivered_sequence.get(key, 0)), key or None)

    def _send_pong(self, peer_id: Optional[int], *, echo_tx_ns: int = 0) -> None:
        key = self._key(peer_id)
        self._send_inner(DeliveryFenceCodec.encode_pong(echo_tx_ns, self._delivered_sequence.get(key, 0)), peer_id)

    def _set_connected(self, connected: bool) -> None:
        if self._connected == bool(connected):
            return
        self._connected = bool(connected)
        if callable(self._on_state):
            self._on_state(self._connected)
        self._connection_lifecycle.transition(
            ConnectionState.CONNECTED if self._connected else ConnectionState.DISCONNECTED,
            self._inner_epoch,
            "delivery_confirmed" if self._connected else "delivery_unconfirmed",
        )

    async def _heartbeat(self) -> None:
        try:
            while self._started:
                if self._inner_ready:
                    self._send_ping_all()
                await asyncio.sleep(self.PING_INTERVAL_S)
        except asyncio.CancelledError:
            return
