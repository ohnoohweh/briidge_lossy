from __future__ import annotations

from obstacle_bridge.tools import fedora_udp_tun_bridge


def test_packet_summary_extracts_ipv4_tcp_metadata() -> None:
    packet = bytes.fromhex(
        "450000341234400040060000c0a8690213d2d243c350005000000000000000005000000000000000"
    )
    summary = fedora_udp_tun_bridge._packet_summary(packet)

    assert summary["ipver"] == 4
    assert summary["proto"] == 6
    assert summary["src"] == "192.168.105.2"
    assert summary["dst"] == "19.210.210.67"
    assert summary["src_port"] == 50000
    assert summary["dst_port"] == 80


def test_arg_parser_accepts_basic_bridge_arguments() -> None:
    parser = fedora_udp_tun_bridge.build_arg_parser()
    args = parser.parse_args(
        [
            "--bind-port",
            "7000",
            "--peer-host",
            "10.10.0.205",
            "--peer-port",
            "7001",
        ]
    )

    assert args.ifname == "obexp0"
    assert args.mtu == 1280
    assert args.bind_host == "0.0.0.0"
    assert args.bind_port == 7000
    assert args.peer_host == "10.10.0.205"
    assert args.peer_port == 7001


def test_packet_ip_version_handles_ipv4_ipv6_and_empty() -> None:
    ipv4 = bytes.fromhex("45000014" + "00" * 16)
    ipv6 = bytes.fromhex("6000000000141140" + "00" * 32)

    assert fedora_udp_tun_bridge._packet_ip_version(ipv4) == 4
    assert fedora_udp_tun_bridge._packet_ip_version(ipv6) == 6
    assert fedora_udp_tun_bridge._packet_ip_version(b"") == -1


def test_arg_parser_accepts_drop_ipv6_flag() -> None:
    parser = fedora_udp_tun_bridge.build_arg_parser()
    args = parser.parse_args(
        [
            "--bind-port",
            "7000",
            "--peer-host",
            "10.10.0.205",
            "--peer-port",
            "7001",
            "--drop-ipv6",
        ]
    )

    assert args.drop_ipv6 is True
