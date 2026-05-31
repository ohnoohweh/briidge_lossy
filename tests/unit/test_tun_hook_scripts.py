from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_server_tun_hook_supports_optional_tcpdump_capture() -> None:
    script = (ROOT / "scripts" / "server-tun-hook.sh").read_text(encoding="utf-8")

    assert 'ENABLE_TUN_TCPDUMP="${ENABLE_TUN_TCPDUMP:-0}"' in script
    assert 'TCPDUMP_PCAP_PATH="${TCPDUMP_PCAP_PATH:-/tmp/ObstacleBridge-${IFNAME}.pcap}"' in script
    assert 'TCPDUMP_PIDFILE="${TCPDUMP_PIDFILE:-/tmp/ObstacleBridge-${IFNAME}.tcpdump.pid}"' in script
    assert 'nohup "$TCPDUMP_BIN" -U -ni "$IFNAME" -w "$TCPDUMP_PCAP_PATH"' in script
    assert "tcpdump_start_if_enabled" in script
    assert "tcpdump_stop_if_enabled" in script


def test_client_tun_hook_brings_interface_up_before_underlay_route_is_known() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'ip addr replace "$TUN_ADDR" dev "$IFNAME"' in script
    assert 'if ! detect_underlay; then' in script
    assert 'leaving ${IFNAME} addressed but skipping default-route changes for now' in script
    assert script.index('ip addr replace "$TUN_ADDR" dev "$IFNAME"') < script.index('if ! detect_underlay; then')
