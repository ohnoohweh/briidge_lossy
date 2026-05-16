from __future__ import annotations

import asyncio
import contextlib
import ctypes
import importlib
import os
import struct
import sys
from typing import Any, Optional


if sys.platform.startswith("win"):
    from ctypes import wintypes
else:
    wintypes = None


def require_tun_support(_mux: Any) -> None:
    if sys.platform.startswith("win"):
        return
    raise RuntimeError("Windows TUN support requested on a non-Windows platform")


def open_tun_device(mux: Any, ifname: str, mtu: int, svc_key: Optional[object] = None):
    mod = None
    if importlib.util.find_spec("wintun") is not None:
        mod = importlib.import_module("wintun")
    elif importlib.util.find_spec("pywintun") is not None:
        mod = importlib.import_module("pywintun")
    else:
        wintun_dir = os.environ.get("WINTUN_DIR")
        if not wintun_dir:
            candidates = []
            pf = os.environ.get("ProgramFiles")
            pfx86 = os.environ.get("ProgramFiles(x86)")
            if pf:
                candidates.append(os.path.join(pf, "Wintun"))
                candidates.append(os.path.join(pf, "wintun"))
            if pfx86:
                candidates.append(os.path.join(pfx86, "Wintun"))
                candidates.append(os.path.join(pfx86, "wintun"))
            candidates.append(os.path.join(os.getcwd(), "wintun"))
            candidates.append(os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), "wintun"))
            for candidate in candidates:
                if candidate and os.path.isdir(candidate):
                    wintun_dir = candidate
                    break
        if wintun_dir and os.path.isdir(wintun_dir):
            parent_dir = os.path.dirname(os.path.abspath(wintun_dir))
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)
            try:
                mod = importlib.import_module("wintun")
            except Exception:
                try:
                    mod = importlib.import_module("pywintun")
                except Exception:
                    mod = None
        if mod is None:
            dll_path = None
            candidates = []
            try:
                is_64 = struct.calcsize("P") * 8 == 64
            except Exception:
                is_64 = sys.maxsize > 2 ** 32

            def push(path: Optional[str]) -> None:
                if path:
                    candidates.append(path)

            env_dir = os.environ.get("WINTUN_DIR")
            if env_dir:
                push(os.path.join(env_dir, "wintun.dll"))
                if is_64:
                    push(os.path.join(env_dir, "bin", "amd64", "wintun.dll"))
                    push(os.path.join(env_dir, "bin", "x64", "wintun.dll"))
                else:
                    push(os.path.join(env_dir, "bin", "x86", "wintun.dll"))
            pf = os.environ.get("ProgramFiles")
            pfx86 = os.environ.get("ProgramFiles(x86)")
            if pf:
                if is_64:
                    push(os.path.join(pf, "Wintun", "wintun.dll"))
                    push(os.path.join(pf, "wintun", "wintun.dll"))
                    push(os.path.join(pf, "wintun", "bin", "amd64", "wintun.dll"))
                else:
                    push(os.path.join(pf, "wintun", "bin", "x86", "wintun.dll"))
            if pfx86:
                push(os.path.join(pfx86, "Wintun", "wintun.dll"))
                push(os.path.join(pfx86, "wintun", "wintun.dll"))
            sysroot = os.environ.get("SystemRoot")
            if sysroot:
                if is_64:
                    push(os.path.join(sysroot, "System32", "wintun.dll"))
                    push(os.path.join(sysroot, "SysWOW64", "wintun.dll"))
                else:
                    push(os.path.join(sysroot, "SysWOW64", "wintun.dll"))
            push(os.path.join(os.getcwd(), "wintun.dll"))
            push(os.path.join(wintun_dir or "", "wintun.dll"))

            for candidate in candidates:
                try:
                    if candidate and os.path.isfile(candidate):
                        dll_path = candidate
                        break
                except Exception:
                    continue

            wintun_lib = None
            load_errors = []
            try_names = [dll_path] if dll_path else []
            try_names.append("wintun.dll")
            for name in try_names:
                try:
                    wintun_lib = ctypes.WinDLL(name)
                    break
                except Exception as exc:
                    load_errors.append((name, exc))
            if wintun_lib is None:
                tried = ", ".join(name for name, _exc in load_errors)
                raise RuntimeError(f"Unable to load wintun.dll; tried: {tried}")

            try:
                wintun_lib.WintunCreateAdapter.restype = ctypes.c_void_p
                wintun_lib.WintunCreateAdapter.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.POINTER(ctypes.c_byte),
                ]
            except Exception:
                pass

            class _CtypesWintunAdapter:
                def __init__(self, lib, name: str):
                    self._lib = lib
                    try:
                        self._adapter = lib.WintunCreateAdapter(
                            ctypes.c_wchar_p(name),
                            ctypes.c_wchar_p("ObstacleBridge"),
                            None,
                        )
                    except Exception as exc:
                        raise RuntimeError(f"WintunCreateAdapter failed: {exc}") from exc
                    if not self._adapter:
                        raise RuntimeError("WintunCreateAdapter returned NULL")
                    try:
                        lib.WintunStartSession.restype = ctypes.c_void_p
                        lib.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
                        self._session = lib.WintunStartSession(self._adapter, 0x400000)
                    except Exception as exc:
                        with contextlib.suppress(Exception):
                            lib.WintunCloseAdapter(self._adapter)
                        raise RuntimeError(f"WintunStartSession failed: {exc}") from exc

                def read_packet(self):
                    packet_size = ctypes.c_uint32()
                    lib = self._lib
                    lib.WintunReceivePacket.restype = ctypes.c_void_p
                    lib.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
                    ptr = lib.WintunReceivePacket(self._session, ctypes.byref(packet_size))
                    if not ptr:
                        return None
                    try:
                        data = ctypes.string_at(ptr, packet_size.value)
                    finally:
                        with contextlib.suppress(Exception):
                            lib.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                            lib.WintunReleaseReceivePacket(self._session, ptr)
                    return data

                def write(self, data: bytes):
                    size = len(data)
                    lib = self._lib
                    lib.WintunAllocateSendPacket.restype = ctypes.c_void_p
                    lib.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
                    ptr = lib.WintunAllocateSendPacket(self._session, ctypes.c_uint32(size))
                    if not ptr:
                        raise RuntimeError("WintunAllocateSendPacket failed or buffer full")
                    ctypes.memmove(ptr, data, size)
                    lib.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                    lib.WintunSendPacket(self._session, ptr)

                def close(self):
                    lib = self._lib
                    with contextlib.suppress(Exception):
                        if getattr(self, "_session", None):
                            lib.WintunEndSession.argtypes = [ctypes.c_void_p]
                            lib.WintunEndSession(self._session)
                    with contextlib.suppress(Exception):
                        if getattr(self, "_adapter", None):
                            lib.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
                            lib.WintunCloseAdapter(self._adapter)

            adapter = _CtypesWintunAdapter(wintun_lib, ifname)
            dev = mux.TunDevice(fd=None, ifname=ifname, mtu=int(mtu), service_key=svc_key)
            setattr(dev, "wintun_adapter", adapter)
            setattr(dev, "reader_registered", False)
            return dev

    create_adapter = getattr(mod, "create_adapter", None) or getattr(mod, "WintunAdapter", None)
    if create_adapter is None:
        raise RuntimeError(
            "Found WinTun package but could not locate adapter creation API. "
            "Please ensure a compatible WinTun wrapper is installed and extend the TUN adapter accordingly."
        )

    try:
        adapter = create_adapter(ifname)
    except Exception as exc:
        raise RuntimeError(f"Failed to create WinTun adapter: {exc}") from exc

    dev = mux.TunDevice(fd=None, ifname=ifname, mtu=int(mtu), service_key=svc_key)
    setattr(dev, "wintun_adapter", adapter)
    setattr(dev, "reader_registered", False)
    return dev


def register_tun_reader(mux: Any, dev: Any) -> None:
    if dev.reader_registered:
        return
    adapter = getattr(dev, "wintun_adapter", None)
    if adapter is None:
        raise RuntimeError("Unable to register TUN reader: no wintun adapter available")
    task = mux.loop.create_task(tun_reader_loop(mux, dev))
    setattr(dev, "wintun_reader_task", task)
    dev.reader_registered = True


def close_tun_device(mux: Any, dev: Any) -> None:
    if dev.reader_registered:
        with contextlib.suppress(Exception):
            task = getattr(dev, "wintun_reader_task", None)
            if task is not None:
                task.cancel()
        dev.reader_registered = False
    with contextlib.suppress(Exception):
        adapter = getattr(dev, "wintun_adapter", None)
        if adapter is not None:
            close_fn = getattr(adapter, "close", None) or getattr(adapter, "shutdown", None) or getattr(adapter, "free", None)
            if callable(close_fn):
                result = close_fn()
                if asyncio.iscoroutine(result):
                    mux.loop.create_task(result)
    dev.chan_id = None


async def tun_reader_loop(mux: Any, dev: Any) -> None:
    adapter = getattr(dev, "wintun_adapter", None)
    if adapter is None:
        return
    read_attr_names = ["read_packet", "read", "recv_packet", "recv", "read_bytes"]
    read_fn = None
    for name in read_attr_names:
        if hasattr(adapter, name):
            read_fn = getattr(adapter, name)
            break
    if read_fn is None and callable(adapter):
        read_fn = adapter
    if read_fn is None:
        mux.log.info("[TUN/WINTUN] adapter for %s has no readable method", dev.ifname)
        return

    loop = mux.loop
    try:
        while True:
            try:
                if asyncio.iscoroutinefunction(read_fn):
                    pkt = await read_fn()
                else:
                    pkt = await loop.run_in_executor(None, read_fn)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                mux.log.info("[TUN/WINTUN] read failed if=%s: %r", dev.ifname, exc)
                await asyncio.sleep(0.1)
                continue
            if not pkt:
                await asyncio.sleep(0.01)
                continue
            try:
                packet = bytes(pkt)
            except Exception:
                packet = pkt
            with contextlib.suppress(Exception):
                loop.call_soon_threadsafe(mux._on_local_tun_packet, dev, packet)
    finally:
        mux.log.info("[TUN/WINTUN] reader loop exiting for %s", dev.ifname)
