#!/usr/bin/env python3
"""Simple WinTun ctypes example.

This script attempts to exercise the ctypes wintun.dll binding:
- load wintun.dll (from WINTUN_DIR, ProgramFiles, System32, or system path)
- create an adapter and start a session
- allocate and send one small packet
- poll for any received packets for `--duration` seconds
- cleanup

This is a best-effort example for development and testing; run as Administrator when
creating adapters on Windows.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
import threading
import time
import random


def find_and_load_wintun():
    candidates = []
    env = os.environ.get("WINTUN_DIR")
    if env:
        candidates.append(os.path.join(env, "wintun.dll"))
    pf = os.environ.get("ProgramFiles")
    pfx86 = os.environ.get("ProgramFiles(x86)")
    if pf:
        candidates.append(os.path.join(pf, "Wintun", "wintun.dll"))
        candidates.append(os.path.join(pf, "wintun", "wintun.dll"))
    if pfx86:
        candidates.append(os.path.join(pfx86, "Wintun", "wintun.dll"))
        candidates.append(os.path.join(pfx86, "wintun", "wintun.dll"))
    sysroot = os.environ.get("SystemRoot")
    if sysroot:
        candidates.append(os.path.join(sysroot, "System32", "wintun.dll"))
        candidates.append(os.path.join(sysroot, "SysWOW64", "wintun.dll"))
    candidates.append(os.path.join(os.getcwd(), "wintun.dll"))

    last_exc = None
    for c in candidates:
        if c and os.path.isfile(c):
            try:
                return ctypes.WinDLL(c)
            except Exception as e:
                last_exc = e
    # fallback: let the system try to resolve the name from PATH/System dirs
    try:
        return ctypes.WinDLL("wintun.dll")
    except Exception as e:
        last_exc = e
    raise RuntimeError(f"Unable to load wintun.dll (tried candidates). Last error: {last_exc}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--duration", type=int, default=5, help="seconds to poll for received packets")
    p.add_argument("--name", default=None, help="adapter name (optional)")
    args = p.parse_args()

    if sys.platform != "win32":
        print("This example is for Windows only.")
        return

    lib = find_and_load_wintun()
    print("Loaded wintun.dll from", getattr(lib, "__file__", "<system>"))

    # Setup restypes/argtypes for functions we will use
    lib.WintunCreateAdapter.restype = ctypes.c_void_p
    lib.WintunCreateAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]

    lib.WintunCloseAdapter.restype = None
    lib.WintunCloseAdapter.argtypes = [ctypes.c_void_p]

    lib.WintunStartSession.restype = ctypes.c_void_p
    lib.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    lib.WintunEndSession.restype = None
    lib.WintunEndSession.argtypes = [ctypes.c_void_p]

    lib.WintunAllocateSendPacket.restype = ctypes.c_void_p
    lib.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    lib.WintunSendPacket.restype = None
    lib.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    lib.WintunReceivePacket.restype = ctypes.c_void_p
    lib.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]

    lib.WintunReleaseReceivePacket.restype = None
    lib.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    # Create adapter
    name = args.name or f"OBExample{random.randrange(0, 10000)}"
    print("Creating adapter:", name)
    adapter = lib.WintunCreateAdapter(ctypes.c_wchar_p(name), ctypes.c_wchar_p("ObstacleBridge"), None)
    if not adapter:
        raise RuntimeError("WintunCreateAdapter failed; ensure driver is installed and you are administrator")
    print("Adapter handle:", adapter)

    try:
        # Start session
        session = lib.WintunStartSession(adapter, 0x400000)
        if not session:
            raise RuntimeError("WintunStartSession failed")
        print("Session started")

        # Receiver thread: poll for packets for a short duration
        stop = threading.Event()

        def receiver():
            endt = time.time() + args.duration
            while not stop.is_set() and time.time() < endt:
                size = ctypes.c_uint32()
                ptr = lib.WintunReceivePacket(session, ctypes.byref(size))
                if not ptr:
                    # nothing available; sleep briefly
                    time.sleep(0.01)
                    continue
                data = ctypes.string_at(ptr, size.value)
                print(f"Received packet size={size.value}")
                # Release buffer
                lib.WintunReleaseReceivePacket(session, ptr)

        th = threading.Thread(target=receiver, daemon=True)
        th.start()

        # send a small test packet if allocation is possible
        test_payload = b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x01" + b"\x00" * 18
        ptr = lib.WintunAllocateSendPacket(session, ctypes.c_uint32(len(test_payload)))
        if not ptr:
            print("WintunAllocateSendPacket returned NULL (buffer full?)")
        else:
            # copy bytes into ptr
            ctypes.memmove(ptr, test_payload, len(test_payload))
            lib.WintunSendPacket(session, ptr)
            print("Sent test packet")

        # wait receiver to finish
        th.join(timeout=args.duration + 1)
        stop.set()

        # cleanup session
        lib.WintunEndSession(session)
        print("Session ended")
    finally:
        try:
            lib.WintunCloseAdapter(adapter)
            print("Adapter closed")
        except Exception:
            pass


if __name__ == "__main__":
    main()
