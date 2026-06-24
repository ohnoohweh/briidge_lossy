from __future__ import annotations

import contextlib
import logging
import os
import socket
import struct
import sys
from typing import Any, Optional

try:
    import fcntl
except Exception:
    fcntl = None


TUN_READ_BURST_MAX = 32


def _record_sync_diag(mux: Any, name: str, *, phase: str, error: str = "") -> None:
    cb = getattr(mux, "_runner_sync_diag_cb", None)
    if not callable(cb):
        return
    with contextlib.suppress(Exception):
        cb(name, kind="callback", phase=phase, error=error)


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


def _tun_ifreq_name(name: str) -> bytes:
    return str(name).encode("utf-8", "ignore")[:15].ljust(16, b"\x00")


def require_tun_support(_mux: Any) -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Linux TUN support requested on a non-Linux platform")
    if fcntl is None:
        raise RuntimeError("TUN services require fcntl support")


def _set_iface_mtu(mux: Any, ifname: str, mtu: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ifr = struct.pack("16sI12x", _tun_ifreq_name(ifname), int(mtu))
        fcntl.ioctl(sock.fileno(), mux.SIOCSIFMTU, ifr)


def _set_iface_up(mux: Any, ifname: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        req = _tun_ifreq_name(ifname) + (b"\x00" * 24)
        res = fcntl.ioctl(sock.fileno(), mux.SIOCGIFFLAGS, req)
        flags = struct.unpack("16xH", res[:18])[0]
        ifr = struct.pack("16sH14x", _tun_ifreq_name(ifname), flags | mux.IFF_UP | mux.IFF_RUNNING)
        fcntl.ioctl(sock.fileno(), mux.SIOCSIFFLAGS, ifr)


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    require_tun_support(mux)
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    try:
        ifr = struct.pack("16sH14x", _tun_ifreq_name(ifname), mux.IFF_TUN | mux.IFF_NO_PI)
        res = fcntl.ioctl(fd, mux.TUNSETIFF, ifr)
        actual = bytes(res[:16]).split(b"\x00", 1)[0].decode("utf-8", "ignore") or ifname
        os.set_blocking(fd, False)
        _set_iface_mtu(mux, actual, mtu)
        _set_iface_up(mux, actual)
        return mux.TunDevice(fd=fd, ifname=actual, mtu=int(mtu), service_key=svc_key)
    except Exception:
        with contextlib.suppress(Exception):
            os.close(fd)
        raise


def register_tun_reader(mux: Any, dev: Any) -> None:
    if dev.reader_registered:
        return
    if getattr(dev, "fd", None) is None:
        raise RuntimeError("Unable to register TUN reader: no tun file descriptor available")
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


def write_tun_packet(_mux: Any, dev: Any, data: bytes) -> None:
    tracer = getattr(_mux, "_log_tun_packet_trace", None)
    if callable(tracer):
        with contextlib.suppress(Exception):
            tracer(stage="platform_tun_write", packet=bytes(data), ifname=str(getattr(dev, "ifname", "") or ""), chan=getattr(dev, "chan_id", None))
    os.write(dev.fd, data)


def on_tun_fd_readable(mux: Any, dev: Any) -> None:
    _record_sync_diag(mux, "bridge_tun_linux.on_tun_fd_readable", phase="started")
    processed = 0
    try:
        while processed < TUN_READ_BURST_MAX:
            try:
                packet = os.read(dev.fd, max(68, min(mux.TUN_READ_SIZE_MAX, int(dev.mtu) + 4)))
            except BlockingIOError:
                return
            except OSError as e:
                if getattr(e, "errno", None) in (11,):
                    return
                mux.log.info("[TUN] if=%s read failed: %r", dev.ifname, e)
                return
            if not packet:
                return
            tracer = getattr(mux, "_log_tun_packet_trace", None)
            if callable(tracer):
                with contextlib.suppress(Exception):
                    tracer(stage="platform_tun_read", packet=bytes(packet), ifname=str(getattr(dev, "ifname", "") or ""), chan=getattr(dev, "chan_id", None))
            checker = getattr(mux.log, "isEnabledFor", None)
            if callable(checker):
                try:
                    if checker(logging.DEBUG):
                        ip_version = (packet[0] >> 4) if packet else -1
                        mux.log.debug(
                            "[TUN/LINUX/PKT] stage=tun_read if=%s len=%s ipver=%s hex=%s",
                            dev.ifname,
                            len(packet),
                            ip_version,
                            packet.hex(),
                        )
                except Exception:
                    pass
            mux._on_local_tun_packet(dev, packet)
            processed += 1
        _schedule_reader_resume(mux, dev)
        checker = getattr(mux.log, "isEnabledFor", None)
        if callable(checker):
            try:
                if checker(logging.DEBUG):
                    mux.log.debug(
                        "[TUN/LINUX] if=%s yielding after burst packets=%s",
                        dev.ifname,
                        processed,
                    )
            except Exception:
                pass
    except Exception as exc:
        _record_sync_diag(mux, "bridge_tun_linux.on_tun_fd_readable", phase="failed", error=type(exc).__name__)
        raise
    finally:
        _record_sync_diag(mux, "bridge_tun_linux.on_tun_fd_readable", phase="finished")
