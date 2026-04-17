"""ObstacleBridge package."""

from .bridge import main as bridge_main
from .core import ObstacleBridgeClient
from .packet_io import MemoryPacketIO, PacketIO

main = bridge_main

__all__ = ["bridge_main", "main", "ObstacleBridgeClient", "PacketIO", "MemoryPacketIO"]
