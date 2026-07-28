from __future__ import annotations

import ipaddress
import socket


PROBE_MAGIC = b"OBTP"
PROBE_KIND_PEER = 1
PROBE_KIND_GLOBAL = 2


def checksum16(payload: bytes) -> int:
    data = bytes(payload or b"")
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) | data[idx + 1]
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def probe_payload(*, probe_kind: int, nonce: bytes, sent_monotonic_ns: int) -> bytes:
    safe_kind = int(probe_kind) & 0xFF
    safe_nonce = bytes(nonce or b"")[:8].ljust(8, b"\x00")
    safe_sent = int(sent_monotonic_ns or 0) & 0xFFFFFFFFFFFFFFFF
    return PROBE_MAGIC + bytes([safe_kind]) + safe_nonce + safe_sent.to_bytes(8, "big")


def build_ipv4_echo_request(
    *,
    source_ip: str,
    destination_ip: str,
    identifier: int,
    sequence: int,
    payload: bytes,
    ttl: int = 64,
    ip_identification: int = 0,
) -> bytes:
    src = ipaddress.IPv4Address(str(source_ip)).packed
    dst = ipaddress.IPv4Address(str(destination_ip)).packed
    icmp = bytearray(8 + len(payload))
    icmp[0] = 8
    icmp[1] = 0
    icmp[4:6] = (int(identifier) & 0xFFFF).to_bytes(2, "big")
    icmp[6:8] = (int(sequence) & 0xFFFF).to_bytes(2, "big")
    icmp[8:] = bytes(payload or b"")
    icmp[2:4] = checksum16(bytes(icmp)).to_bytes(2, "big")

    total_length = 20 + len(icmp)
    header = bytearray(20)
    header[0] = 0x45
    header[1] = 0
    header[2:4] = int(total_length).to_bytes(2, "big")
    header[4:6] = (int(ip_identification) & 0xFFFF).to_bytes(2, "big")
    header[6:8] = b"\x00\x00"
    header[8] = max(1, min(255, int(ttl)))
    header[9] = 1
    header[12:16] = src
    header[16:20] = dst
    header[10:12] = checksum16(bytes(header)).to_bytes(2, "big")
    return bytes(header) + bytes(icmp)


def build_ipv6_echo_request(
    *,
    source_ip: str,
    destination_ip: str,
    identifier: int,
    sequence: int,
    payload: bytes,
    hop_limit: int = 64,
) -> bytes:
    src = ipaddress.IPv6Address(str(source_ip)).packed
    dst = ipaddress.IPv6Address(str(destination_ip)).packed
    icmp = bytearray(8 + len(payload))
    icmp[0] = 128
    icmp[1] = 0
    icmp[4:6] = (int(identifier) & 0xFFFF).to_bytes(2, "big")
    icmp[6:8] = (int(sequence) & 0xFFFF).to_bytes(2, "big")
    icmp[8:] = bytes(payload or b"")
    pseudo = src + dst + len(icmp).to_bytes(4, "big") + (b"\x00" * 3) + bytes([58]) + bytes(icmp)
    icmp[2:4] = checksum16(pseudo).to_bytes(2, "big")

    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = len(icmp).to_bytes(2, "big")
    header[6] = 58
    header[7] = max(1, min(255, int(hop_limit)))
    header[8:24] = src
    header[24:40] = dst
    return bytes(header) + bytes(icmp)


def parse_echo_reply(packet: bytes) -> dict[str, object] | None:
    data = bytes(packet or b"")
    if not data:
        return None
    version = int((data[0] >> 4) & 0x0F)
    if version == 4:
        if len(data) < 28:
            return None
        ihl = int(data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl + 8 or int(data[9]) != 1:
            return None
        payload = data[ihl:]
        if payload[0] != 0 or payload[1] != 0 or len(payload) < 8:
            return None
        return {
            "family": socket.AF_INET,
            "source_ip": str(ipaddress.IPv4Address(data[12:16])),
            "destination_ip": str(ipaddress.IPv4Address(data[16:20])),
            "identifier": int.from_bytes(payload[4:6], "big"),
            "sequence": int.from_bytes(payload[6:8], "big"),
            "payload": bytes(payload[8:]),
        }
    if version == 6:
        if len(data) < 48 or int(data[6]) != 58:
            return None
        payload = data[40:]
        if payload[0] != 129 or payload[1] != 0 or len(payload) < 8:
            return None
        return {
            "family": socket.AF_INET6,
            "source_ip": str(ipaddress.IPv6Address(data[8:24])),
            "destination_ip": str(ipaddress.IPv6Address(data[24:40])),
            "identifier": int.from_bytes(payload[4:6], "big"),
            "sequence": int.from_bytes(payload[6:8], "big"),
            "payload": bytes(payload[8:]),
        }
    return None


def ip_family(value: str) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    return socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
