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
import time
from collections import OrderedDict
from typing import Any, Callable, Optional

from .bridge_connection_lifecycle import ConnectionLifecycleEmitter, ConnectionState
from .bridge_transport_common import DeliveryFenceCodec


class DeliveryFenceSession:
    LAYER = "delivery_fence"
    MAX_PENDING_BYTES = 4 * 1024 * 1024
    PING_INTERVAL_S = 0.5

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._log = logging.getLogger("delivery_fence")
        self._on_app: Optional[Callable[..., None]] = None
        self._on_state: Optional[Callable[[bool], None]] = None
        self._connection_lifecycle = ConnectionLifecycleEmitter()
        self._inner_epoch = 0
        self._started = False
        self._inner_ready = False
        self._connected = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._next_sequence: dict[int, int] = {}
        self._delivered_sequence: dict[int, int] = {}
        self._confirmed_sequence: dict[int, int] = {}
        self._pending: dict[int, OrderedDict[int, bytes]] = {}
        self._pending_bytes = 0
        inner.set_on_app_payload(self._on_inner_app)
        inner.set_on_state_change(self._on_inner_state)
        setter = getattr(inner, "set_on_connection_lifecycle", None)
        if callable(setter):
            setter(self._on_inner_lifecycle)

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
    def set_on_transport_epoch_change(self, cb: Callable[[int], None]) -> None: self._inner.set_on_transport_epoch_change(cb)
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
            self._replay_all()
            self._send_ping_all()
        else:
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
            self._replay_all()
            self._send_ping_all()
        else:
            self._inner_ready = False
            self._set_connected(False)
            self._connection_lifecycle.transition(
                ConnectionState.DISCONNECTED,
                self._inner_epoch,
                str(getattr(event, "reason", "") or "inner_disconnected"),
            )

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
        self._set_connected(True)

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
        keys = set(self._pending) | set(self._delivered_sequence) | {0}
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
