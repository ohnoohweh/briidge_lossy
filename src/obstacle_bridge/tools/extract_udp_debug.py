#!/usr/bin/env python3
"""
[docstring unchanged for brevity]
"""
import argparse
import struct
import zlib

from scapy.all import PcapReader, UDP, IP, IPv6  # pip install scapy

# -------------------- Constants --------------------
PORT_OUT = 40000  # Session -> Mux mirror
PORT_IN = 40001   # Mux -> Session mirror

# Show at most 20 bytes of payload in the final column
DISPLAY_MAX = 20

# ChannelMux v2 header according to ObstacleBridge.py (>HBHBH):
# chan_id(2), proto(1), counter(2), mtype(1), data_len(2)
MUX_HDR = struct.Struct(">HBHBH")

PROTO_NAME = {0: "UDP", 1: "TCP"}                 # from ObstacleBridge.py
MTYPE_NAME = {0: "DATA", 1: "OPEN", 2: "CLOSE"}   # from ObstacleBridge.py


# -------------------- Helpers (unchanged) --------------------
def is_loopback_v4(pkt) -> bool:
    return IP in pkt and pkt[IP].src == "127.0.0.1" and pkt[IP].dst == "127.0.0.1"

def is_loopback_v6(pkt) -> bool:
    return IPv6 in pkt and pkt[IPv6].src == "::1" and pkt[IPv6].dst == "::1"

def classify_direction(dst_port: int, side: str) -> str:
    if side == "client":
        return "A-B" if dst_port == PORT_OUT else "B-A"
    else:  # server
        return "B-A" if dst_port == PORT_OUT else "A-B"

def udp_payload(pkt) -> bytes:
    try:
        return bytes(pkt[UDP].payload) if UDP in pkt else b""
    except Exception:
        return b""

def crc32_hex_u8(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08X}"

def dir_matches(direction: str, want: str) -> bool:
    return True if want == "both" else (direction == want)


# -------------------- MUX parsing --------------------
def parse_mux(payload: bytes):
    """
    Returns:
      (proto_str, chan_id, counter, mtype_str, data_len, peek_bytes_after_hdr)
    or None if no full header.
    """
    if len(payload) < MUX_HDR.size:
        return None
    try:
        chan_id, proto_b, counter, mtype_b, data_len = MUX_HDR.unpack_from(payload, 0)
    except struct.error:
        return None

    proto_s = PROTO_NAME.get(proto_b, f"0x{proto_b:02X}")
    mtype_s = MTYPE_NAME.get(mtype_b, f"0x{mtype_b:02X}")

    # Only bytes AFTER the MUX header are considered payload for display:
    remaining = max(0, len(payload) - MUX_HDR.size)
    n = min(DISPLAY_MAX, data_len, remaining)   # <-- enforce 20-byte max display
    peek = payload[MUX_HDR.size:MUX_HDR.size + n]
    return proto_s, chan_id, counter, mtype_s, data_len, peek


# -------------------- Main --------------------
def main():
    ap = argparse.ArgumentParser(
        description=("Extract <frame(5)> <direction> <udp_payload_size(5)> <CRC32> "
                     "<proto(1): chan_id(2)> <counter(2)> <mtype(1)> <data_len(2)> <pay_hex[:N]> "
                     "from a pcap/pcapng for loopback UDP to ports 40000/40001.")
    )
    ap.add_argument("pcap", help="Path to .pcap/.pcapng")
    ap.add_argument("--side", choices=["client", "server"], default="client",
                    help="Which side captured this pcap (affects A-B/B-A mapping). Default: client.")
    ap.add_argument("--dir", choices=["A-B", "B-A", "both"], default="both",
                    help="Optional direction filter. Default: both.")
    args = ap.parse_args()

    frame = 0
    with PcapReader(args.pcap) as rd:
        for pkt in rd:
            if UDP not in pkt:
                continue
            if not (is_loopback_v4(pkt) or is_loopback_v6(pkt)):
                continue
            dport = int(pkt[UDP].dport)
            if dport not in (PORT_OUT, PORT_IN):
                continue

            payload = udp_payload(pkt)
            direction = classify_direction(dport, args.side)
            if not dir_matches(direction, args.dir):
                continue

            frame += 1
            frame_str = f"{frame:05d}"
            size_str = f"{len(payload):05d}"
            crc_str = crc32_hex_u8(payload)

            parsed = parse_mux(payload)
            if parsed is not None:
                proto_s, chan_id, counter, mtype_s, data_len, peek = parsed
                hdr_part = f"{proto_s}: {chan_id}"
                counter_part = f"{counter}"
                mtype_part = f"{mtype_s}"
                dlen_part = f"{data_len}"
                peek_hex = peek.hex().upper()
            else:
                # No/short MUX header -> show at most 20 bytes from raw payload
                hdr_part = "—: —"
                counter_part = "—"
                mtype_part = "—"
                dlen_part = "—"
                peek_hex = payload[:DISPLAY_MAX].hex().upper()

            line = (
                f"{frame_str} {direction} {size_str} {crc_str} "
                f"{hdr_part} {counter_part} {mtype_part} {dlen_part} {peek_hex}"
            )
            print(line)


if __name__ == "__main__":
    main()