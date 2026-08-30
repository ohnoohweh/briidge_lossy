from __future__ import annotations

import contextlib
import ipaddress
import logging
import struct
from typing import Optional

from ._bridge_import import export_bridge_globals

_bridge = export_bridge_globals(globals())


class PeerAddressProtocolSession(ISession):
    """Reflect the client source IP observed by the connected overlay server."""

    _HEADER = struct.Struct(">4sBBB")
    _MAGIC = b"OBPA"
    _VERSION = 2
    _TYPE_REQUEST = 1
    _TYPE_REPLY = 2

    def __init__(self, inner: ISession, *, transport_name: str, client_mode: bool) -> None:
        self._inner = inner
        self._transport_name = str(transport_name or "")
        self._client_mode = bool(client_mode)
        self._outer_on_app = None
        self._outer_on_state = None
        self._observed_public_ip = ""
        self._observed_public_port = 0
        self._request_sent = False
        self._log = logging.getLogger("peer_address_protocol")

    def __getattr__(self, name):
        return getattr(self._inner, name)

    @classmethod
    def _request_frame(cls) -> bytes:
        return cls._HEADER.pack(cls._MAGIC, cls._VERSION, cls._TYPE_REQUEST, 0)

    @classmethod
    def _reply_frame(cls, host: str, port: int) -> bytes:
        address = ipaddress.ip_address(str(host).split("%", 1)[0])
        # A dual-stack listener can report an IPv4 client as ::ffff:a.b.c.d.
        # Publish that as IPv4: it is the same network path and must match the
        # resolved IPv4 peer shown in the operator UI.
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        family = 4 if address.version == 4 else 6
        return cls._HEADER.pack(cls._MAGIC, cls._VERSION, cls._TYPE_REPLY, family) + address.packed + struct.pack(">H", port)

    @classmethod
    def _parse_control_frame(cls, payload: bytes) -> Optional[tuple[int, str, int]]:
        if len(payload) < cls._HEADER.size:
            return None
        magic, version, frame_type, family = cls._HEADER.unpack(payload[: cls._HEADER.size])
        if magic != cls._MAGIC or version != cls._VERSION:
            return None
        body = payload[cls._HEADER.size :]
        if frame_type == cls._TYPE_REQUEST and family == 0 and not body:
            return frame_type, "", 0
        expected = 4 if family == 4 else 16 if family == 6 else 0
        if frame_type != cls._TYPE_REPLY or expected == 0 or len(body) != expected + 2:
            return None
        with contextlib.suppress(ValueError):
            port = struct.unpack(">H", body[expected:])[0]
            if 1 <= port <= 65535:
                return frame_type, str(ipaddress.ip_address(body[:expected])), port
        return None

    def set_on_app_payload(self, cb) -> None:
        self._outer_on_app = cb

    def set_on_state_change(self, cb) -> None:
        self._outer_on_state = cb

    def set_on_connection_lifecycle(self, cb) -> None:
        setter = getattr(self._inner, "set_on_connection_lifecycle", None)
        if callable(setter):
            setter(cb)

    def set_on_peer_rx(self, cb) -> None:
        setter = getattr(self._inner, "set_on_peer_rx", None)
        if callable(setter):
            setter(cb)

    def set_on_peer_tx(self, cb) -> None:
        setter = getattr(self._inner, "set_on_peer_tx", None)
        if callable(setter):
            setter(cb)

    def set_on_peer_set(self, cb) -> None:
        setter = getattr(self._inner, "set_on_peer_set", None)
        if callable(setter):
            setter(cb)

    def set_on_peer_disconnect(self, cb) -> None:
        setter = getattr(self._inner, "set_on_peer_disconnect", None)
        if callable(setter):
            setter(cb)

    def set_on_app_from_peer_bytes(self, cb) -> None:
        setter = getattr(self._inner, "set_on_app_from_peer_bytes", None)
        if callable(setter):
            setter(cb)

    def set_on_transport_epoch_change(self, cb) -> None:
        setter = getattr(self._inner, "set_on_transport_epoch_change", None)
        if callable(setter):
            setter(cb)

    def _on_inner_state_change(self, connected: bool) -> None:
        if not connected:
            self._request_sent = False
            self._observed_public_ip = ""
            self._observed_public_port = 0
        elif self._client_mode and not self._request_sent:
            self._request_sent = bool(self._inner.send_app(self._request_frame()))
        if callable(self._outer_on_state):
            self._outer_on_state(bool(connected))

    def _observed_peer_endpoint(self, peer_id: Optional[int]) -> tuple[str, int]:
        getter = getattr(self._inner, "get_overlay_peers_snapshot", None)
        rows = list(getter() or []) if callable(getter) else []
        for row in rows:
            if bool(row.get("listening")):
                continue
            if peer_id is not None and int(row.get("peer_id", -1)) != int(peer_id):
                continue
            endpoint = row.get("peer")
            host = endpoint.get("host") if isinstance(endpoint, dict) else ""
            port = endpoint.get("port") if isinstance(endpoint, dict) else 0
            with contextlib.suppress(ValueError):
                port = int(port)
                if 1 <= port <= 65535:
                    return str(ipaddress.ip_address(str(host).split("%", 1)[0])), port
        return "", 0

    def _deliver_outer(self, payload: bytes, peer_id: Optional[int]) -> None:
        if not callable(self._outer_on_app):
            return
        try:
            self._outer_on_app(payload, peer_id=peer_id)
        except TypeError:
            self._outer_on_app(payload)

    def _on_inner_payload(self, payload: bytes, peer_id: Optional[int] = None) -> None:
        parsed = self._parse_control_frame(bytes(payload or b""))
        if parsed is None:
            self._deliver_outer(payload, peer_id)
            return
        frame_type, address, port = parsed
        if frame_type == self._TYPE_REQUEST and not self._client_mode:
            observed_host, observed_port = self._observed_peer_endpoint(peer_id)
            if observed_host:
                self._inner.send_app(self._reply_frame(observed_host, observed_port), peer_id=peer_id)
            return
        if frame_type == self._TYPE_REPLY and self._client_mode:
            self._observed_public_ip = address
            self._observed_public_port = port
            self._log.info(
                "[PEER-ADDRESS] server-observed source transport=%s family=ipv%s address=%s port=%s",
                self._transport_name,
                ipaddress.ip_address(address).version,
                address,
                port,
            )
            return

    async def start(self) -> None:
        self._inner.set_on_app_payload(self._on_inner_payload)
        self._inner.set_on_state_change(self._on_inner_state_change)
        await self._inner.start()

    async def stop(self) -> None:
        self._request_sent = False
        self._observed_public_ip = ""
        self._observed_public_port = 0
        await self._inner.stop()

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        waiter = getattr(self._inner, "wait_connected", None)
        return bool(await waiter(timeout=timeout)) if callable(waiter) else self.is_connected()

    def is_connected(self) -> bool:
        return bool(getattr(self._inner, "is_connected", lambda: False)())

    def get_metrics(self):
        getter = getattr(self._inner, "get_metrics", None)
        return getter() if callable(getter) else None

    def get_max_app_payload_size(self) -> int:
        getter = getattr(self._inner, "get_max_app_payload_size", None)
        return int(getter() or 65535) if callable(getter) else 65535

    def request_connection_rotation(self, reason: str = ""):
        requester = getattr(self._inner, "request_connection_rotation", None)
        return requester(reason) if callable(requester) else None

    def send_app(self, payload: bytes, peer_id: Optional[int] = None) -> int:
        return self._inner.send_app(payload, peer_id=peer_id)

    def get_overlay_peers_snapshot(self) -> list[dict]:
        getter = getattr(self._inner, "get_overlay_peers_snapshot", None)
        rows = [dict(row) for row in list(getter() or [])] if callable(getter) else []
        if self._client_mode:
            for row in rows:
                if not bool(row.get("listening")) and int(row.get("peer_id", 0)) == 0:
                    row["observed_public_ip"] = self._observed_public_ip
                    row["observed_public_port"] = self._observed_public_port or None
        return rows

    def get_connection_layers_snapshot(self) -> list[dict[str, object]]:
        getter = getattr(self._inner, "get_connection_layers_snapshot", None)
        layers = list(getter() or []) if callable(getter) else []
        transport_connected = bool(getattr(self._inner, "is_connected", lambda: False)())
        layers.append(
            {
                "layer": "peer_address_protocol",
                "transport": self._transport_name,
                "state": "resolved" if self._observed_public_ip else "discovering" if self._client_mode and transport_connected else "disconnected" if self._client_mode else "passive",
                "epoch": 0,
                "connected": transport_connected,
                "app_ready": transport_connected,
                "observed_public_ip": self._observed_public_ip,
                "observed_public_port": self._observed_public_port or None,
            }
        )
        return layers
