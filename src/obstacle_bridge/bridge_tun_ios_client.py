from __future__ import annotations

import sys
from typing import Any, Optional

from . import bridge_tun_ios as platform
from . import bridge_tun_ios_server as server


def require_tun_support(_mux: Any) -> None:
    if sys.platform != "ios":
        raise RuntimeError("iOS TUN support requested on a non-iOS platform")
    if platform._swift_native_packetflow_owned():
        return
    state = platform._bridge_state()
    if not state.get("active"):
        raise RuntimeError("iOS packet flow bridge is not active inside the packet tunnel provider")


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    require_tun_support(mux)
    if getattr(mux, "_svc_tun_devices", {}):
        raise RuntimeError(
            "iOS packet tunnel currently supports one live NEPacketTunnelFlow-backed TUN device at a time"
        )
    return server.open_tun_device(mux, ifname, mtu, svc_key=svc_key)


def register_tun_reader(mux: Any, dev: Any) -> None:
    server.register_tun_reader(mux, dev)


def close_tun_device(mux: Any, dev: Any) -> None:
    server.close_tun_device(mux, dev)


def write_tun_packet(mux: Any, dev: Any, data: bytes) -> None:
    server.write_tun_packet(mux, dev, data)