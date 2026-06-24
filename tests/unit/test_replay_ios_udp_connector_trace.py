from __future__ import annotations

import socket
import threading

from obstacle_bridge.bridge_tun_ios import _RawPacketPCAPWriter
from obstacle_bridge.tools import replay_ios_udp_connector_trace


def test_replay_ios_udp_connector_trace_replays_packets(tmp_path):
    pcap_path = tmp_path / "capture.pcap"
    writer = _RawPacketPCAPWriter(pcap_path)
    try:
        writer.write_packet(b"\x45one", timestamp=1000.0)
        writer.write_packet(b"\x45two", timestamp=1000.1)
    finally:
        writer.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = int(server.getsockname()[1])
    received: list[bytes] = []

    def _reader() -> None:
        try:
            for _ in range(2):
                payload, _addr = server.recvfrom(65535)
                received.append(payload)
        finally:
            server.close()

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()
    try:
        rc = replay_ios_udp_connector_trace.main(
            [str(pcap_path), "--host", "127.0.0.1", "--port", str(port)]
        )
        assert rc == 0
        thread.join(timeout=2.0)
    finally:
        try:
            server.close()
        except Exception:
            pass

    assert received == [b"\x45one", b"\x45two"]
