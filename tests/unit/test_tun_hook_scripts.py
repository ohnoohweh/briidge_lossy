from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_server_tun_hook_supports_optional_tcpdump_capture() -> None:
    script = (ROOT / "scripts" / "server-tun-hook.sh").read_text(encoding="utf-8")

    assert ': "${PEER_ADDR:?missing PEER_ADDR}"' not in script
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


def test_client_tun_hook_preserves_saved_underlay_default_across_repeated_up() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'current_default="$(ip route show default | head -n1 || true)"' in script
    assert '"$current_default" != *" dev ${IFNAME}"*' in script
    assert 'current_default6="$(ip -6 route show default | head -n1 || true)"' in script
    assert '"$current_default6" != *" dev ${IFNAME}"*' in script


def test_client_tun_hook_normalizes_ipv4_mapped_ipv6_peer_for_route_programming() -> None:
    script = (ROOT / "scripts" / "client-tun-hook.sh").read_text(encoding="utf-8")

    assert 'normalize_overlay_peer_ip() {' in script
    assert '^::ffff:([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$' in script
    assert 'normalized_ip="$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")"' in script
    assert 'printf \x27%s/32\x27 "$normalized_ip"' in script or "printf '%s/32' \"$normalized_ip\"" in script


def test_macos_client_tun_hook_configures_point_to_point_utun_and_default_route() -> None:
    script = (ROOT / "scripts" / "client-tun-hook-macos.sh").read_text(encoding="utf-8")

    assert 'EXCLUDED_ROUTES="${EXCLUDED_ROUTES:-127.0.0.0/8}"' in script
    assert 'EXCLUDED_ROUTES6="${EXCLUDED_ROUTES6:-::1/128}"' in script
    assert 'ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$TUN_GW" netmask "$(ipv4_prefix_to_netmask "$TUN_ADDR_PREFIX")" up' in script
    assert 'route -n get default' in script
    assert 'netstat -rn -f inet' in script
    assert 'netstat -rn -f inet6' in script
    assert 'route -n add default -interface "$IFNAME"' in script
    assert 'default_matches_v4() {' in script
    assert 'expand_included_routes_v6() {' in script
    assert 'full_tunnel_v6_matches() {' in script
    assert 'case "$route_spec" in' in script
    assert '"::/0"|"default"|"::0/0")' in script
    assert 'printf \'%s\\n\' "::/1"' in script
    assert 'printf \'%s\\n\' "8000::/1"' in script
    assert 'route -n delete default -interface "$IFNAME"' in script
    assert 'delete_included_routes_v6' in script
    assert 'add_excluded_routes_v4() {' in script
    assert 'add_excluded_routes_v6() {' in script
    assert 'delete_excluded_routes_v4() {' in script
    assert 'delete_excluded_routes_v6() {' in script
    assert 'snapshot_excluded_routes_v4() {' in script
    assert 'snapshot_excluded_routes_v6() {' in script
    assert 'route -n get -inet6 "$probe"' in script
    assert "while IFS='|' read -r route_spec underlay_gw underlay_if; do" in script
    assert 'add_excluded_routes_v4' in script
    assert 'add_excluded_routes_v6' in script
    assert 'normalize_overlay_peer_ip() {' in script
    assert 'route -n add -host "$(normalize_overlay_peer_ip "$OVERLAY_PEER_IP")" "$local_underlay_gw"' in script


def test_macos_server_tun_hook_brings_utun_up_with_peer_identity() -> None:
    script = (ROOT / "scripts" / "server-tun-hook-macos.sh").read_text(encoding="utf-8")

    assert 'ifconfig "$IFNAME" inet "$TUN_ADDR_IP" "$PEER_ADDR" up' in script
    assert 'ifconfig "$IFNAME" down' in script
