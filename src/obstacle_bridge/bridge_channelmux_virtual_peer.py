from __future__ import annotations

from typing import Any, Optional

from ._bridge_import import export_bridge_globals
from .bridge_tun_ping import parse_internal_probe_packet

_bridge = export_bridge_globals(globals())

ChannelMux = None


class ChannelMuxVirtualPeerMixin:
    SHARED_TUN_LOCAL_PROBE_PEER_REF = "__local_probe__"
    SHARED_TUN_LOCAL_PROBE_PEER_ID = 0
    SHARED_TUN_LOCAL_PROBE_CHAN_ID = -1

    def _shared_tun_local_probe_binding_for_service(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
    ) -> Optional[dict[str, Any]]:
        if not isinstance(svc_key, tuple) or str(svc_key[0]) != "local":
            return None
        if svc_key not in self._shared_tun_ownership_by_service:
            return None
        cfg = self._tun_routing_config()
        ipv4 = str(getattr(cfg, "global_connectivity_source_ipv4", "") or "").strip()
        if not ipv4:
            return None
        return {
            "peer_id": self.SHARED_TUN_LOCAL_PROBE_PEER_ID,
            "peer_ref": self.SHARED_TUN_LOCAL_PROBE_PEER_REF,
            "preferred_chan_id": self.SHARED_TUN_LOCAL_PROBE_CHAN_ID,
            "bound_chan_ids": [self.SHARED_TUN_LOCAL_PROBE_CHAN_ID],
            "ipv4": [ipv4],
            "ipv6": [],
            "address_count": 1,
            "local_virtual": True,
            "throttle_prev_window_bytes": 0,
            "throttle_curr_window_bytes": 0,
            "throttle_drop_count": 0,
        }
    def _shared_tun_active_peer_bindings_for_service(
        self,
        svc_key: Optional["ChannelMux.ServiceKey"],
    ) -> list[dict[str, Any]]:
        if svc_key is None:
            return []
        active_peer_bindings = [
            {
                "peer_id": int(key[1]),
                "peer_ref": "",
                "preferred_chan_id": state.get("preferred_chan_id"),
                "bound_chan_ids": [int(v) for v in list(state.get("bound_chan_ids") or [])],
                "throttle_prev_window_bytes": 0,
                "throttle_curr_window_bytes": 0,
                "throttle_drop_count": 0,
                "local_virtual": False,
            }
            for key, state in self._shared_tun_runtime_by_peer.items()
            if key[0] == svc_key and isinstance(state, dict)
        ]
        local_virtual_peer = self._shared_tun_local_probe_binding_for_service(svc_key)
        if local_virtual_peer is not None:
            active_peer_bindings.append(local_virtual_peer)
        active_peer_bindings.sort(key=lambda entry: int(entry.get("peer_id", 0)))
        return active_peer_bindings
    @classmethod
    def _is_local_virtual_probe_chan_id(cls, chan_id: Optional[int]) -> bool:
        return chan_id is not None and int(chan_id) == int(cls.SHARED_TUN_LOCAL_PROBE_CHAN_ID)
    def _source_address_for_probe(
        self,
        *,
        probe_kind: str,
        family: int,
    ) -> str:
        if family == socket.AF_INET:
            override = str(self._tun_routing_config().global_connectivity_source_ipv4 or "").strip()
            if override:
                return override
        return self._source_address_for_probe_family(family)
    def _probe_should_use_kernel_tun_injection(
        self,
        dev: "ChannelMux.TunDevice",
        *,
        family: int,
        source_ip: str,
    ) -> bool:
        if family != socket.AF_INET or not sys.platform.startswith("linux"):
            return False
        if str(source_ip or "").strip() != self._source_address_for_probe_family(family):
            return False
        svc_key = getattr(dev, "service_key", None)
        if not isinstance(svc_key, tuple) or str(svc_key[0]) != "local":
            return False
        snapshot = self._shared_tun_runtime_snapshot_for_service(svc_key)
        if not isinstance(snapshot, dict):
            return False
        active_peer_bindings = [
            entry
            for entry in list(snapshot.get("active_peer_bindings") or [])
            if isinstance(entry, dict) and not bool(entry.get("local_virtual")) and entry.get("preferred_chan_id") is not None
        ]
        return len(active_peer_bindings) == 1
    def _probe_uses_local_virtual_injection(
        self,
        dev: "ChannelMux.TunDevice",
        *,
        family: int,
        source_ip: str,
    ) -> bool:
        svc_key = getattr(dev, "service_key", None)
        local_virtual_peer = self._shared_tun_local_probe_binding_for_service(svc_key)
        if not isinstance(local_virtual_peer, dict):
            return False
        local_virtual_ipv4 = str(next(iter(list(local_virtual_peer.get("ipv4") or [])), "") or "").strip()
        return (
            family == socket.AF_INET
            and bool(local_virtual_ipv4)
            and str(source_ip or "").strip() == local_virtual_ipv4
        )
    def _local_virtual_probe_transport_active(self) -> bool:
        return bool(self._overlay_connected and self._accepting_enabled and self._session_app_ready())
    @staticmethod
    def _send_probe_packet_via_kernel_tun_blocking(
        *,
        ifname: str,
        family: int,
        destination_ip: str,
        packet: bytes,
    ) -> None:
        if family != socket.AF_INET:
            raise RuntimeError(f"kernel TUN probe injection unsupported for family={family}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            ifname_bytes = str(ifname or "").strip().encode("ascii", "strict")
            if ifname_bytes:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname_bytes + b"\x00")
            sock.sendto(bytes(packet or b""), (str(destination_ip or "").strip(), 0))
        finally:
            sock.close()
    async def _send_probe_packet_via_local_tun(
        self,
        dev: "ChannelMux.TunDevice",
        *,
        family: int,
        source_ip: str,
        destination_ip: str,
        packet: bytes,
    ) -> None:
        svc_key = getattr(dev, "service_key", None)
        if self._probe_uses_local_virtual_injection(dev, family=family, source_ip=source_ip):
            self._record_tun_probe_boundary("probe_injected_local_virtual")
            self._dispatch_local_virtual_probe_packet(dev, packet)
            return
        if self._probe_should_use_kernel_tun_injection(dev, family=family, source_ip=source_ip):
            self._record_tun_probe_boundary("probe_injected_kernel")
            await asyncio.to_thread(
                self._send_probe_packet_via_kernel_tun_blocking,
                ifname=str(getattr(dev, "ifname", "") or ""),
                family=int(family),
                destination_ip=str(destination_ip or ""),
                packet=bytes(packet or b""),
            )
            return
        self._record_tun_probe_boundary("probe_injected_channelmux")
        self._on_local_tun_packet(dev, packet)
    @staticmethod
    def _parse_internal_tun_probe_packet(packet: bytes) -> Optional[dict[str, Any]]:
        parsed = parse_internal_probe_packet(packet)
        if not isinstance(parsed, dict):
            return None
        return parsed
    def _dispatch_local_virtual_probe_packet(
        self,
        dev: "ChannelMux.TunDevice",
        packet: bytes,
    ) -> None:
        self._dispatch_shared_tun_inbound_packet(
            dev,
            packet,
            source_peer_id=self.SHARED_TUN_LOCAL_PROBE_PEER_ID,
            source_chan_id=self.SHARED_TUN_LOCAL_PROBE_CHAN_ID,
            source_note="local_virtual_probe",
        )
    def _handle_local_virtual_probe_delivery(
        self,
        dev: "ChannelMux.TunDevice",
        packet: bytes,
        *,
        route_class: Optional[str] = None,
    ) -> bool:
        if self._observe_tun_probe_reply(dev, packet):
            self.log.debug(
                "[TUN] if=%s consumed local virtual probe reply route_class=%s",
                str(getattr(dev, "ifname", "") or ""),
                str(route_class or ""),
            )
            return True
        parsed, _ = self._parse_tun_packet_endpoints(packet)
        self._record_shared_tun_drop(
            getattr(dev, "service_key", None),
            reason="local_virtual_unhandled_packet",
            direction="local_to_virtual",
            peer_id=self.SHARED_TUN_LOCAL_PROBE_PEER_ID,
            chan_id=self.SHARED_TUN_LOCAL_PROBE_CHAN_ID,
            ip_version=None if parsed is None else parsed.get("ip_version"),
            source_ip=None if parsed is None else parsed.get("source_ip"),
            destination_ip=None if parsed is None else parsed.get("destination_ip"),
            route_class=route_class,
            packet_bytes=len(packet),
        )
        self.log.debug(
            "[TUN] if=%s drop local virtual packet route_class=%s src=%s dst=%s",
            str(getattr(dev, "ifname", "") or ""),
            str(route_class or ""),
            None if parsed is None else parsed.get("source_ip"),
            None if parsed is None else parsed.get("destination_ip"),
        )
        return False
