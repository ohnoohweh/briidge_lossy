from __future__ import annotations

import asyncio
import argparse
import contextlib
import ctypes
import json
import logging
import os
import socket
import struct
import sys
import time
from collections import deque
from ctypes import POINTER, c_bool, c_char, c_char_p, c_int, c_size_t, c_void_p, cast
from ctypes.util import find_library
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple


IOS_TUN_CONNECTOR_SECTION = "iOS_TUN_connector"
DEFAULT_IOS_PACKETFLOW_BIND_HOST = "0.0.0.0"
DEFAULT_IOS_PACKETFLOW_BIND_PORT = 5555
DEFAULT_IOS_SWIFT_UDP_SHIM_HOST = "127.0.0.1"
DEFAULT_IOS_PACKETFLOW_IFNAME = "ios-utun"
DEFAULT_IOS_PACKETFLOW_MTU = 1280


@dataclass
class IOSTUNConnectorSettings:
    packetflow_connector: str = ""
    peer_host: str = ""
    peer_port: int = 0
    bind_host: str = DEFAULT_IOS_PACKETFLOW_BIND_HOST
    bind_port: int = DEFAULT_IOS_PACKETFLOW_BIND_PORT
    ifname: str = DEFAULT_IOS_PACKETFLOW_IFNAME
    mtu: int = DEFAULT_IOS_PACKETFLOW_MTU

    @staticmethod
    def register_cli(p: argparse.ArgumentParser) -> None:
        g = p.add_argument_group(IOS_TUN_CONNECTOR_SECTION)
        g.add_argument(
            "--packetflow-connector",
            default="",
            choices=["", "udp", "direct", "simple_udp_peer", "swift_udp", "swift_udp_peer", "swift_host_runner"],
            help="iOS packetflow connector mode for native and Python packet tunnel handoff",
        )
        g.add_argument("--ios-tun-connector-peer-host", dest="peer_host", default="", help="peer host for simple_udp_peer packetflow mode")
        g.add_argument("--ios-tun-connector-peer-port", dest="peer_port", type=int, default=0, help="peer port for simple_udp_peer packetflow mode")

    @classmethod
    def from_mapping(
        cls,
        config: Mapping[str, Any] | None,
        *,
        base: Optional["IOSTUNConnectorSettings"] = None,
    ) -> "IOSTUNConnectorSettings":
        current = base if base is not None else cls()
        source: Mapping[str, Any] = config or {}
        values: Mapping[str, Any] = source
        if isinstance(source, Mapping):
            group = source.get(IOS_TUN_CONNECTOR_SECTION)
            if isinstance(group, Mapping):
                values = group
        return cls(
            packetflow_connector=str(values.get("packetflow_connector") or current.packetflow_connector).strip(),
            peer_host=str(values.get("peer_host") or current.peer_host).strip(),
            peer_port=int(values.get("peer_port") or current.peer_port),
            bind_host=str(values.get("bind_host") or current.bind_host).strip() or current.bind_host,
            bind_port=int(values.get("bind_port") or current.bind_port),
            ifname=str(values.get("ifname") or current.ifname).strip() or current.ifname,
            mtu=int(values.get("mtu") or current.mtu),
        )


def packetflow_connector_mode_from_config(config: Mapping[str, Any] | None) -> str:
    raw = str(os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "") or "").strip().lower()
    if raw:
        return "swift_udp" if raw == "swift_udp_peer" else raw
    settings = IOSTUNConnectorSettings.from_mapping(config)
    mode = str(settings.packetflow_connector or "").strip().lower()
    return "swift_udp" if mode == "swift_udp_peer" else mode


def simple_udp_peer_settings(config: Mapping[str, Any] | None) -> dict[str, Any] | None:
    grouped = dict(config) if isinstance(config, Mapping) else {}
    settings = IOSTUNConnectorSettings.from_mapping(grouped)
    flat = dict(grouped)

    def _pick(*keys: str, default: Any = "") -> Any:
        for key in keys:
            if key in os.environ and str(os.environ[key]).strip():
                return os.environ[key]
        for key in keys:
            value = getattr(settings, key, None)
            if value not in (None, ""):
                return value
        for key in keys:
            if key in flat and flat.get(key) not in (None, ""):
                return flat.get(key)
        return default

    connector_mode = str(
        _pick(
            "OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR",
            "packetflow_connector",
            "ios_packetflow_connector",
            default="",
        )
        or ""
    ).strip().lower()
    if connector_mode != "simple_udp_peer":
        return None
    peer_host = str(
        _pick(
            "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST",
            "peer_host",
            "ios_packetflow_peer_host",
            default="",
        )
        or ""
    ).strip()
    peer_port_raw = _pick(
        "OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT",
        "peer_port",
        "ios_packetflow_peer_port",
        default=0,
    )
    bind_host = str(
        _pick(
            "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST",
            "bind_host",
            "ios_packetflow_udp_host",
            default=DEFAULT_IOS_PACKETFLOW_BIND_HOST,
        )
        or DEFAULT_IOS_PACKETFLOW_BIND_HOST
    ).strip()
    bind_port_raw = _pick(
        "OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT",
        "bind_port",
        "ios_packetflow_udp_port",
        default=DEFAULT_IOS_PACKETFLOW_BIND_PORT,
    )
    ifname = str(_pick("ifname", "ios_packetflow_ifname", default=DEFAULT_IOS_PACKETFLOW_IFNAME) or DEFAULT_IOS_PACKETFLOW_IFNAME).strip()
    mtu_raw = _pick("mtu", "ios_packetflow_mtu", default=DEFAULT_IOS_PACKETFLOW_MTU)
    peer_port = int(peer_port_raw) if str(peer_port_raw).strip() else 0
    bind_port = int(bind_port_raw) if str(bind_port_raw).strip() else DEFAULT_IOS_PACKETFLOW_BIND_PORT
    mtu = int(mtu_raw) if str(mtu_raw).strip() else DEFAULT_IOS_PACKETFLOW_MTU
    if not peer_host or peer_port <= 0:
        raise ValueError("simple_udp_peer mode requires peer_host and peer_port")
    return {
        "connector_mode": "simple_udp_peer",
        "peer_host": peer_host,
        "peer_port": peer_port,
        "bind_host": bind_host,
        "bind_port": bind_port,
        "ifname": ifname or DEFAULT_IOS_PACKETFLOW_IFNAME,
        "mtu": max(68, int(mtu)),
    }


def simple_udp_peer_runtime_config(config: Mapping[str, Any] | None) -> dict[str, Any] | None:
    settings = simple_udp_peer_settings(config)
    if settings is None:
        return None
    runtime_cfg = dict(config) if isinstance(config, Mapping) else {}
    merged = dict(runtime_cfg.get(IOS_TUN_CONNECTOR_SECTION) or {}) if isinstance(runtime_cfg.get(IOS_TUN_CONNECTOR_SECTION), Mapping) else {}
    merged.update(
        {
            "packetflow_connector": "simple_udp_peer",
            "peer_host": settings["peer_host"],
            "peer_port": settings["peer_port"],
            "bind_host": settings["bind_host"],
            "bind_port": settings["bind_port"],
            "ifname": settings["ifname"],
            "mtu": settings["mtu"],
        }
    )
    runtime_cfg[IOS_TUN_CONNECTOR_SECTION] = merged
    return runtime_cfg


def swift_udp_runtime_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(config) if isinstance(config, Mapping) else {}


def swift_udp_shim_settings(config: Mapping[str, Any] | None) -> dict[str, Any] | None:
    mode = packetflow_connector_mode_from_config(config)
    if mode != "swift_udp":
        return None
    settings = IOSTUNConnectorSettings.from_mapping(config)
    bind_host = str(
        os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_HOST", "")
        or settings.bind_host
        or DEFAULT_IOS_SWIFT_UDP_SHIM_HOST
    ).strip() or DEFAULT_IOS_SWIFT_UDP_SHIM_HOST
    bind_port = int(
        os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP_PORT", "")
        or settings.bind_port
        or DEFAULT_IOS_PACKETFLOW_BIND_PORT
    )
    shim_host = str(
        os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST", "")
        or DEFAULT_IOS_SWIFT_UDP_SHIM_HOST
    ).strip() or DEFAULT_IOS_SWIFT_UDP_SHIM_HOST
    shim_port = int(
        os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT", "")
        or (bind_port + 1)
    )
    return {
        "connector_mode": "swift_udp",
        "swift_bind_host": bind_host,
        "swift_bind_port": bind_port,
        "shim_host": shim_host,
        "shim_port": shim_port,
        "ifname": settings.ifname or DEFAULT_IOS_PACKETFLOW_IFNAME,
        "mtu": max(68, int(settings.mtu or DEFAULT_IOS_PACKETFLOW_MTU)),
    }


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

    def register_wakeup_fd(self, fd: int) -> bool:
        return bool(
            self._send(
                self._bridge_cls,
                "registerWakeupFD:",
                c_bool,
                c_int(int(fd)),
                argtypes=[c_int],
            )
        )

    def reset_wakeup_fd(self) -> None:
        self._send(self._bridge_cls, "resetWakeupFD", None, argtypes=[])


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


def _option_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "udp"}:
        return True
    if text in {"0", "false", "no", "off", "direct"}:
        return False
    return None


def _udp_connector_enabled(dev: Optional[Any] = None) -> bool:
    mode = _packetflow_connector_mode(dev)
    return mode in {"udp", "simple_udp_peer"}


def _packetflow_connector_mode(dev: Optional[Any] = None) -> str:
    options = getattr(dev, "ios_packetflow_options", None)
    if isinstance(options, dict):
        for key in ("ios_packetflow_udp", "packetflow_udp", "udp_connector"):
            chosen = _option_bool(options.get(key))
            if chosen is not None:
                return "udp" if chosen else "direct"
        mode = str(options.get("ios_packetflow_connector", "") or "").strip().lower()
        if mode:
            if mode == "swift_udp_peer":
                return "swift_udp"
            if mode in {"udp", "direct", "simple_udp_peer", "swift_udp", "swift_host_runner"}:
                return mode
    mode = os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", "")
    if mode.strip():
        selected = mode.strip().lower()
        if selected == "swift_udp_peer":
            return "swift_udp"
        if selected in {"udp", "direct", "simple_udp_peer", "swift_udp", "swift_host_runner"}:
            return selected
    return "udp" if _option_bool(os.environ.get("OBSTACLEBRIDGE_IOS_PACKETFLOW_UDP")) is True else "direct"


def _swift_native_packetflow_owned(dev: Optional[Any] = None) -> bool:
    return _packetflow_connector_mode(dev) == "swift_udp"


def _udp_option(options: dict[str, Any], key: str, env_key: str, default: Any) -> Any:
    if env_key in os.environ:
        return os.environ[env_key]
    if key in options:
        return options[key]
    return default


class _RawPacketPCAPWriter:
    _GLOBAL_HDR = struct.Struct("<IHHIIII")
    _RECORD_HDR = struct.Struct("<IIII")
    _DLT_RAW = 101

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("wb")
        self._fh.write(self._GLOBAL_HDR.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, self._DLT_RAW))
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def write_packet(self, packet: bytes, *, timestamp: Optional[float] = None) -> None:
        payload = bytes(packet or b"")
        stamp = time.time() if timestamp is None else float(timestamp)
        seconds = int(stamp)
        micros = max(0, min(999_999, int((stamp - seconds) * 1_000_000.0)))
        length = min(len(payload), 0xFFFFFFFF)
        self._fh.write(self._RECORD_HDR.pack(seconds, micros, length, length))
        self._fh.write(payload[:length])
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        try:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except Exception:
            pass
        self._fh.close()


def _capture_timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _connector_logs_root() -> Optional[Path]:
    root = str(os.environ.get("OBSTACLEBRIDGE_IOS_DIAGNOSTICS_ROOT", "") or "").strip()
    if root:
        return Path(root)
    state = _bridge_state()
    for key in ("incoming_pcap_path", "outgoing_pcap_path"):
        raw = str(state.get(key, "") or "").strip()
        if raw:
            return Path(raw).expanduser().resolve().parent
    return None


def _packet_summary(packet: bytes) -> dict[str, Any]:
    data = bytes(packet or b"")
    summary: dict[str, Any] = {"len": len(data), "ipver": -1}
    if not data:
        return summary
    ipver = (data[0] >> 4) & 0xF
    summary["ipver"] = ipver
    if ipver == 4 and len(data) >= 20:
        ihl = max(20, (data[0] & 0x0F) * 4)
        proto = int(data[9])
        summary["proto"] = proto
        summary["src"] = ".".join(str(b) for b in data[12:16])
        summary["dst"] = ".".join(str(b) for b in data[16:20])
        if len(data) >= ihl + 4 and proto in {6, 17}:
            summary["src_port"] = int.from_bytes(data[ihl : ihl + 2], "big")
            summary["dst_port"] = int.from_bytes(data[ihl + 2 : ihl + 4], "big")
    elif ipver == 6 and len(data) >= 40:
        proto = int(data[6])
        summary["proto"] = proto
        with contextlib.suppress(Exception):
            summary["src"] = socket.inet_ntop(socket.AF_INET6, data[8:24])
            summary["dst"] = socket.inet_ntop(socket.AF_INET6, data[24:40])
        if len(data) >= 44 and proto in {6, 17}:
            summary["src_port"] = int.from_bytes(data[40:42], "big")
            summary["dst_port"] = int.from_bytes(data[42:44], "big")
    return summary


from . import bridge_tun_ios_client as _client
from . import bridge_tun_ios_server as _server

PacketFlowOnlyMux = _server.PacketFlowOnlyMux
SimpleUDPPeerRuntime = _server.SimpleUDPPeerRuntime
require_tun_support = _client.require_tun_support
open_tun_device = _client.open_tun_device
register_tun_reader = _client.register_tun_reader
close_tun_device = _client.close_tun_device
write_tun_packet = _client.write_tun_packet
