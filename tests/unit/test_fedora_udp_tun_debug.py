from __future__ import annotations

from obstacle_bridge.tools import fedora_udp_tun_debug


def test_arg_parser_accepts_interface_overrides() -> None:
    parser = fedora_udp_tun_debug.build_arg_parser()
    args = parser.parse_args(
        [
            "--tun-if",
            "obexp9",
            "--uplink-if",
            "wlan0",
            "--output",
            "/tmp/fedora-debug.txt",
        ]
    )

    assert args.tun_if == "obexp9"
    assert args.uplink_if == "wlan0"
    assert args.route_ipv4 == "1.1.1.1"
    assert args.route_ipv4_src == "192.168.105.1"
    assert args.route_ipv6 == "2606:4700:4700::1111"
    assert args.route_ipv6_src == "fd20:105::1"
    assert args.output == "/tmp/fedora-debug.txt"
