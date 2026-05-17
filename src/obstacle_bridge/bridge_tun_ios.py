from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import sys
from ctypes import POINTER, c_bool, c_char, c_char_p, c_size_t, c_void_p, cast
from ctypes.util import find_library
from typing import Any, Optional


def _load_cdll(name: str) -> Any:
    path = find_library(name)
    if path:
        return ctypes.CDLL(path)
    for candidate in (
        f"/usr/lib/lib{name}.dylib",
        f"/System/Library/Frameworks/{name}.framework/{name}",
    ):
        try:
            return ctypes.CDLL(candidate)
        except OSError:
            continue
    raise OSError(f"library not found: {name}")


def _objc_callable(libobjc: Any, restype: Any, argtypes: list[Any]) -> Any:
    return ctypes.CFUNCTYPE(restype, c_void_p, c_void_p, *argtypes)(("objc_msgSend", libobjc))


class _PacketFlowBridgeBackend:
    def __init__(self) -> None:
        self._libobjc = _load_cdll("objc")
        self._libobjc.objc_getClass.restype = c_void_p
        self._libobjc.objc_getClass.argtypes = [c_char_p]
        self._libobjc.sel_registerName.restype = c_void_p
        self._libobjc.sel_registerName.argtypes = [c_char_p]
        self._nsdata_cls = self._class("NSData")
        self._bridge_cls = self._class("ObstacleBridgePacketFlowBridge")

    def _class(self, name: str) -> c_void_p:
        ptr = self._libobjc.objc_getClass(name.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Objective-C class not found: {name}")
        return ptr

    def _sel(self, name: str) -> c_void_p:
        ptr = self._libobjc.sel_registerName(name.encode("utf-8"))
        if not ptr:
            raise RuntimeError(f"Objective-C selector not found: {name}")
        return ptr

    def _send(self, target: c_void_p, selector: str, restype: Any, *args: Any, argtypes: list[Any]) -> Any:
        fn = _objc_callable(self._libobjc, restype, argtypes)
        return fn(target, self._sel(selector), *args)

    def _wrap(self, value: bytes) -> c_void_p:
        payload = bytes(value or b"")
        buf = ctypes.create_string_buffer(payload, len(payload))
        return self._send(
            self._nsdata_cls,
            "dataWithBytes:length:",
            c_void_p,
            cast(buf, c_void_p),
            c_size_t(len(payload)),
            argtypes=[c_void_p, c_size_t],
        )

    def _unwrap_optional_data(self, value: Any) -> Optional[bytes]:
        if not value:
            return None
        target = c_void_p(value) if not isinstance(value, c_void_p) else value
        length = self._send(target, "length", c_size_t, argtypes=[])
        bytes_ptr = self._send(target, "bytes", c_void_p, argtypes=[])
        return bytes(cast(bytes_ptr, POINTER(c_char))[: int(length)])

    def dequeue_packet(self) -> Optional[bytes]:
        data = self._send(self._bridge_cls, "dequeueIncomingPacket", c_void_p, argtypes=[])
        return self._unwrap_optional_data(data)

    def write_packet(self, packet: bytes) -> bool:
        return bool(
            self._send(
                self._bridge_cls,
                "writePacket:",
                c_bool,
                self._wrap(packet),
                argtypes=[c_void_p],
            )
        )

    def bridge_state(self) -> dict[str, Any]:
        raw = self._send(self._bridge_cls, "bridgeStateJSONData", c_void_p, argtypes=[])
        data = self._unwrap_optional_data(raw)
        if not data:
            return {}
        try:
            decoded = json.loads(data.decode("utf-8"))
        except Exception:
            return {}
        return decoded if isinstance(decoded, dict) else {}


_BACKEND: Optional[_PacketFlowBridgeBackend] = None


def _backend() -> _PacketFlowBridgeBackend:
    global _BACKEND
    if _BACKEND is None:
        _BACKEND = _PacketFlowBridgeBackend()
    return _BACKEND


def _bridge_state() -> dict[str, Any]:
    try:
        return _backend().bridge_state()
    except Exception:
        return {}


def _debug_enabled(log: Any) -> bool:
    checker = getattr(log, "isEnabledFor", None)
    if callable(checker):
        try:
            return bool(checker(logging.DEBUG))
        except Exception:
            return False
    return False


def _log_packet_debug(log: Any, *, stage: str, ifname: str, packet: bytes) -> None:
    if not _debug_enabled(log):
        return
    payload = bytes(packet or b"")
    ip_version = (payload[0] >> 4) if payload else -1
    log.debug(
        "[TUN/IOS/PKT] stage=%s if=%s len=%s ipver=%s hex=%s",
        stage,
        ifname,
        len(payload),
        ip_version,
        payload.hex(),
    )


def require_tun_support(_mux: Any) -> None:
    if sys.platform != "ios":
        raise RuntimeError("iOS TUN support requested on a non-iOS platform")
    state = _bridge_state()
    if not state.get("active"):
        raise RuntimeError("iOS packet flow bridge is not active inside the packet tunnel provider")


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    require_tun_support(mux)
    if getattr(mux, "_svc_tun_devices", {}):
        raise RuntimeError(
            "iOS packet tunnel currently supports one live NEPacketTunnelFlow-backed TUN device at a time"
        )
    state = _bridge_state()
    mux.log.info("[TUN/IOS] open if=%s mtu=%s bridge_state=%s", ifname, mtu, state)
    return mux.TunDevice(fd=-1, ifname=ifname, mtu=int(mtu), service_key=svc_key)


async def _reader_loop(mux: Any, dev: Any) -> None:
    idle_sleep_s = 0.01
    burst_limit = 64
    packets_seen = 0
    mux.log.info("[TUN/IOS] reader loop starting if=%s mtu=%s", dev.ifname, dev.mtu)
    try:
        while True:
            delivered = 0
            for _ in range(burst_limit):
                packet = _backend().dequeue_packet()
                if packet is None:
                    break
                delivered += 1
                packets_seen += 1
                _log_packet_debug(mux.log, stage="packet_flow_read", ifname=dev.ifname, packet=packet)
                if packets_seen <= 3 or packets_seen % 64 == 0:
                    mux.log.info(
                        "[TUN/IOS] inbound packet if=%s len=%s total_packets=%s",
                        dev.ifname,
                        len(packet),
                        packets_seen,
                    )
                mux._on_local_tun_packet(dev, packet)
            if delivered == 0:
                await asyncio.sleep(idle_sleep_s)
            else:
                await asyncio.sleep(0)
    except asyncio.CancelledError:
        mux.log.info("[TUN/IOS] reader loop cancelled if=%s packets_seen=%s", dev.ifname, packets_seen)
        raise
    except Exception as exc:
        mux.log.exception("[TUN/IOS] reader loop failed if=%s: %r", dev.ifname, exc)


def register_tun_reader(mux: Any, dev: Any) -> None:
    if getattr(dev, "reader_registered", False):
        return
    task = mux.loop.create_task(_reader_loop(mux, dev))
    setattr(dev, "reader_task", task)
    setattr(dev, "reader_registered", True)
    mux.log.info("[TUN/IOS] reader registered if=%s bridge_state=%s", dev.ifname, _bridge_state())


def close_tun_device(mux: Any, dev: Any) -> None:
    task = getattr(dev, "reader_task", None)
    if task is not None:
        task.cancel()
    setattr(dev, "reader_registered", False)
    mux.log.info("[TUN/IOS] close if=%s bridge_state=%s", dev.ifname, _bridge_state())


def write_tun_packet(mux: Any, dev: Any, data: bytes) -> None:
    _log_packet_debug(mux.log, stage="packet_flow_write", ifname=dev.ifname, packet=data)
    try:
        ok = _backend().write_packet(data)
    except Exception as exc:
        mux.log.info("[TUN/IOS] write failed if=%s: %r", dev.ifname, exc)
        raise
    if not ok:
        raise RuntimeError("iOS packet flow bridge rejected outbound packet write")
