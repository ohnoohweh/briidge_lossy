"""Packet I/O abstractions for embeddable TUN-style runtimes."""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Deque, Iterable, Protocol, runtime_checkable


@runtime_checkable
class PacketIO(Protocol):
    """Async packet boundary used by platform TUN providers.

    Desktop implementations can adapt Linux ``/dev/net/tun`` or WinTun to this
    protocol. Mobile implementations can adapt iOS ``NEPacketTunnelFlow`` to the
    same shape without exposing platform APIs to the overlay core.
    """

    async def read_packets(self) -> list[bytes]:
        """Return one or more packets read from the platform interface."""
        ...

    async def write_packets(self, packets: Iterable[bytes]) -> None:
        """Write one or more packets to the platform interface."""
        ...


class MemoryPacketIO:
    """In-memory PacketIO implementation for tests and early embedder spikes."""

    def __init__(self) -> None:
        self._incoming: Deque[bytes] = deque()
        self._outgoing: Deque[bytes] = deque()
        self._incoming_ready = asyncio.Event()

    def feed_incoming(self, packet: bytes) -> None:
        self._incoming.append(bytes(packet))
        self._incoming_ready.set()

    async def read_packets(self) -> list[bytes]:
        while not self._incoming:
            await self._incoming_ready.wait()
        packets = list(self._incoming)
        self._incoming.clear()
        self._incoming_ready.clear()
        return packets

    async def write_packets(self, packets: Iterable[bytes]) -> None:
        for packet in packets:
            self._outgoing.append(bytes(packet))

    def drain_outgoing(self) -> list[bytes]:
        packets = list(self._outgoing)
        self._outgoing.clear()
        return packets
