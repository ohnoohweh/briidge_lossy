from __future__ import annotations

import contextlib
import ctypes
import logging
import os
import socket
import struct
import subprocess
import sys
from typing import Any, Optional

try:
    import fcntl
except Exception:
    fcntl = None


TUN_READ_BURST_MAX = 32


CTLIOCGINFO = 0xC0644E03
UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
UTUN_OPT_IFNAME = 2
AF_SYS_CONTROL = 2
AF_SYSTEM = getattr(socket, "AF_SYSTEM", 32)
PF_SYSTEM = getattr(socket, "PF_SYSTEM", AF_SYSTEM)
SYSPROTO_CONTROL = getattr(socket, "SYSPROTO_CONTROL", 2)
_LIBC = ctypes.CDLL(None, use_errno=True)


class _CtlInfo(ctypes.Structure):
    _fields_ = [
        ("ctl_id", ctypes.c_uint32),
        ("ctl_name", ctypes.c_char * 96),
    ]


class _SockaddrCtl(ctypes.Structure):
    _fields_ = [
        ("sc_len", ctypes.c_ubyte),
        ("sc_family", ctypes.c_ubyte),
        ("ss_sysaddr", ctypes.c_uint16),
        ("sc_id", ctypes.c_uint32),
        ("sc_unit", ctypes.c_uint32),
        ("sc_reserved", ctypes.c_uint32 * 5),
    ]


_LIBC.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
_LIBC.connect.restype = ctypes.c_int


def _record_sync_diag(mux: Any, name: str, *, phase: str, error: str = "") -> None:
    cb = getattr(mux, "_runner_sync_diag_cb", None)
    if not callable(cb):
        return
    with contextlib.suppress(Exception):
        cb(name, kind="callback", phase=phase, error=error)


def require_tun_support(_mux: Any) -> None:
    if not sys.platform.startswith("darwin"):
        raise RuntimeError("macOS TUN support requested on a non-macOS platform")
    if fcntl is None:
        raise RuntimeError("macOS TUN services require fcntl support")
    if PF_SYSTEM is None or AF_SYSTEM is None:
        raise RuntimeError("macOS TUN services require AF_SYSTEM/PF_SYSTEM support")


def _lookup_utun_control_id(fd: int) -> int:
    info = _CtlInfo()
    info.ctl_name = UTUN_CONTROL_NAME
    fcntl.ioctl(fd, CTLIOCGINFO, info)
    ctl_id = int(info.ctl_id)
    if ctl_id <= 0:
        raise RuntimeError("unable to resolve utun control id")
    return ctl_id


def _connect_utun(fd: int, control_id: int, unit: int = 0) -> None:
    addr = _SockaddrCtl()
    addr.sc_len = ctypes.sizeof(_SockaddrCtl)
    addr.sc_family = AF_SYSTEM
    addr.ss_sysaddr = AF_SYS_CONTROL
    addr.sc_id = int(control_id)
    addr.sc_unit = int(unit)
    rc = _LIBC.connect(fd, ctypes.byref(addr), ctypes.sizeof(addr))
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _query_utun_ifname(sock: socket.socket, requested_ifname: str) -> str:
    raw = sock.getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 64)
    actual = bytes(raw).split(b"\x00", 1)[0].decode("utf-8", "ignore").strip()
    return actual or requested_ifname


def _set_iface_mtu_and_up(mux: Any, ifname: str, mtu: int) -> None:
    try:
        subprocess.run(
            ["ifconfig", ifname, "mtu", str(int(mtu)), "up"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        with contextlib.suppress(Exception):
            mux.log.info("[TUN/MACOS] ifconfig mtu/up skipped for %s: %r", ifname, exc)


def _family_prefix_for_packet(packet: bytes) -> bytes:
    if not packet:
        raise RuntimeError("cannot write empty packet to macOS utun")
    version = packet[0] >> 4
    if version == 4:
        family = socket.AF_INET
    elif version == 6:
        family = socket.AF_INET6
    else:
        raise RuntimeError(f"unsupported IP version for macOS utun packet: {version}")
    return struct.pack("!I", int(family))


def _packet_from_utun_frame(frame: bytes) -> bytes:
    if len(frame) < 4:
        return b""
    family_be = struct.unpack("!I", frame[:4])[0]
    family_native = struct.unpack("=I", frame[:4])[0]
    if family_be in (socket.AF_INET, socket.AF_INET6):
        return frame[4:]
    if family_native in (socket.AF_INET, socket.AF_INET6):
        return frame[4:]
    return frame[4:]


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    require_tun_support(mux)
    sock = socket.socket(PF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
    try:
        control_id = _lookup_utun_control_id(sock.fileno())
        _connect_utun(sock.fileno(), control_id)
        actual = _query_utun_ifname(sock, ifname)
        fd = sock.detach()
        os.set_blocking(fd, False)
        _set_iface_mtu_and_up(mux, actual, mtu)
        return mux.TunDevice(fd=fd, ifname=actual, mtu=int(mtu), service_key=svc_key)
    except OSError as exc:
        with contextlib.suppress(Exception):
            sock.close()
        if getattr(exc, "errno", None) == 1:
            raise RuntimeError(
                "macOS utun creation requires elevated privileges or an allowed execution context"
            ) from exc
        raise
    except Exception:
        with contextlib.suppress(Exception):
            sock.close()
        raise


def _schedule_reader_resume(mux: Any, dev: Any) -> None:
    if getattr(dev, "_reader_yield_scheduled", False):
        return
    was_registered = bool(getattr(dev, "reader_registered", False))
    if was_registered and getattr(dev, "fd", None) is not None:
        with contextlib.suppress(Exception):
            mux.loop.remove_reader(dev.fd)
        dev.reader_registered = False
    setattr(dev, "_reader_yield_scheduled", True)

    def _resume() -> None:
        setattr(dev, "_reader_yield_scheduled", False)
        if was_registered:
            with contextlib.suppress(Exception):
                register_tun_reader(mux, dev)
            return
        on_tun_fd_readable(mux, dev)

    mux.loop.call_soon(_resume)


def register_tun_reader(mux: Any, dev: Any) -> None:
    if dev.reader_registered:
        return
    if getattr(dev, "fd", None) is None:
        raise RuntimeError("Unable to register macOS TUN reader: no utun file descriptor available")
    mux.loop.add_reader(dev.fd, on_tun_fd_readable, mux, dev)
    dev.reader_registered = True


def close_tun_device(mux: Any, dev: Any) -> None:
    if dev.reader_registered:
        with contextlib.suppress(Exception):
            if getattr(dev, "fd", None) is not None:
                mux.loop.remove_reader(dev.fd)
        dev.reader_registered = False
    with contextlib.suppress(Exception):
        if getattr(dev, "fd", None) is not None:
            os.close(dev.fd)
    dev.chan_id = None


def write_tun_packet(mux: Any, dev: Any, data: bytes) -> None:
    frame = _family_prefix_for_packet(data) + bytes(data)
    tracer = getattr(mux, "_log_tun_packet_trace", None)
    if callable(tracer):
        with contextlib.suppress(Exception):
            tracer(stage="platform_tun_write", packet=bytes(data), ifname=str(getattr(dev, "ifname", "") or ""), chan=getattr(dev, "chan_id", None))
    checker = getattr(mux.log, "isEnabledFor", None)
    if callable(checker):
        with contextlib.suppress(Exception):
            if checker(logging.DEBUG):
                mux.log.debug(
                    "[TUN/MACOS/PKT] stage=tun_write if=%s len=%s ipver=%s hex=%s",
                    dev.ifname,
                    len(data),
                    (data[0] >> 4) if data else -1,
                    data.hex(),
                )
    os.write(dev.fd, frame)


def on_tun_fd_readable(mux: Any, dev: Any) -> None:
    _record_sync_diag(mux, "bridge_tun_macos.on_tun_fd_readable", phase="started")
    processed = 0
    try:
        while processed < TUN_READ_BURST_MAX:
            try:
                frame = os.read(dev.fd, max(72, min(mux.TUN_READ_SIZE_MAX, int(dev.mtu) + 4)))
            except BlockingIOError:
                return
            except OSError as exc:
                if getattr(exc, "errno", None) in (11,):
                    return
                mux.log.info("[TUN/MACOS] if=%s read failed: %r", dev.ifname, exc)
                return
            if not frame:
                return
            packet = _packet_from_utun_frame(frame)
            if not packet:
                continue
            tracer = getattr(mux, "_log_tun_packet_trace", None)
            if callable(tracer):
                with contextlib.suppress(Exception):
                    tracer(stage="platform_tun_read", packet=bytes(packet), ifname=str(getattr(dev, "ifname", "") or ""), chan=getattr(dev, "chan_id", None))
            checker = getattr(mux.log, "isEnabledFor", None)
            if callable(checker):
                with contextlib.suppress(Exception):
                    if checker(logging.DEBUG):
                        mux.log.debug(
                            "[TUN/MACOS/PKT] stage=tun_read if=%s len=%s ipver=%s hex=%s",
                            dev.ifname,
                            len(packet),
                            (packet[0] >> 4) if packet else -1,
                            packet.hex(),
                        )
            mux._on_local_tun_packet(dev, packet)
            processed += 1
        _schedule_reader_resume(mux, dev)
        checker = getattr(mux.log, "isEnabledFor", None)
        if callable(checker):
            with contextlib.suppress(Exception):
                if checker(logging.DEBUG):
                    mux.log.debug(
                        "[TUN/MACOS] if=%s yielding after burst packets=%s",
                        dev.ifname,
                        processed,
                    )
    except Exception as exc:
        _record_sync_diag(mux, "bridge_tun_macos.on_tun_fd_readable", phase="failed", error=type(exc).__name__)
        raise
    finally:
        _record_sync_diag(mux, "bridge_tun_macos.on_tun_fd_readable", phase="finished")
