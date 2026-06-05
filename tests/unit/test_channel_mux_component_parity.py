from __future__ import annotations

import json
import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from obstacle_bridge.bridge import ChannelMux
from tests.unit.test_channel_mux_listener_mode import _FakeSession, _ipv4_packet, _ipv6_packet
from tests.unit.test_channel_mux_swift_parity import (
    ROOT,
    SWIFT_CODEC_SOURCE,
    SWIFT_CHANNELMUX_TUN_RUNTIME_SOURCE,
    _python_channelmux_inbound_tun_fragment_sequence_summary,
    _python_channelmux_local_tun_packet_summary,
    _python_channelmux_tun_close_then_local_packet_summary,
    _python_channelmux_tun_open_then_local_packet_summary,
)


SWIFT_COMPONENT_RUNNER_SOURCE = ROOT / "tests" / "fixtures" / "channelmux_component_runner.swift"


@pytest.fixture(scope="session")
def swift_channelmux_component_runner(tmp_path_factory: pytest.TempPathFactory) -> Path:
    swiftc = shutil.which("swiftc")
    if swiftc is None:
        pytest.skip("swiftc is required for Swift component parity tests")
    output_dir = tmp_path_factory.mktemp("swift_channelmux_component")
    binary = output_dir / "channelmux_component_runner"
    command = [
        swiftc,
        "-o",
        str(binary),
        str(SWIFT_CODEC_SOURCE),
        str(SWIFT_CHANNELMUX_TUN_RUNTIME_SOURCE),
        str(SWIFT_COMPONENT_RUNNER_SOURCE),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"failed to compile Swift ChannelMux component runner\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return binary


def _run_swift_component(binary: Path, request: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        [str(binary)],
        input=json.dumps(request),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Swift component runner failed\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def _python_guarded_inbound_tun_data_summary(
    *,
    packet: bytes,
    allowed_source_ips: set[str] | None,
) -> dict[str, object]:
    mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
    try:
        svc_key = ("peer", 77, 2)
        dev = ChannelMux.TunDevice(fd=44, ifname="obtun1", mtu=1500, service_key=svc_key)
        mux._tun_by_chan[7] = dev
        mux._chan_owner_peer_id[7] = 77
        if allowed_source_ips:
            ipv4 = sorted(addr for addr in allowed_source_ips if ":" not in addr)
            ipv6 = sorted(addr for addr in allowed_source_ips if ":" in addr)
            spec = ChannelMux.ServiceSpec(
                2,
                "tun",
                "obtun1",
                1500,
                "tun",
                "obtun0",
                1500,
                options={
                    "shared_tun_ownership": {
                        "mode": "server_shared",
                        "peers": [
                            {
                                "peer_ref": "linux-client",
                                "ipv4": ipv4,
                                "ipv6": ipv6,
                            }
                        ],
                    }
                },
            )
            mux._install_shared_tun_ownership_for_service(svc_key, spec)
        allowed, parsed, reason = mux._shared_tun_guard_inbound_packet(dev=dev, chan=7, packet=packet)
        return {
            "delivered": bool(allowed),
            "packet_hex": packet.hex() if allowed else None,
            "ip_version": None if parsed is None else parsed.get("ip_version"),
            "source_ip": None if parsed is None else parsed.get("source_ip"),
            "destination_ip": None if parsed is None else parsed.get("destination_ip"),
            "drop_reason": reason,
        }
    finally:
        mux.loop.close()


def _python_shared_tun_outbound_route_summary(
    *,
    packet: bytes,
    owner_by_ipv4: dict[str, str],
    owner_by_ipv6: dict[str, str],
    peer_id_by_ref: dict[str, int],
    active_peer_bindings: list[dict[str, object]],
) -> dict[str, object]:
    return ChannelMux._shared_tun_plan_outbound_route(
        {
            "owner_by_ipv4": owner_by_ipv4,
            "owner_by_ipv6": owner_by_ipv6,
        },
        peer_id_by_ref,
        active_peer_bindings,
        packet,
    )


def _python_shared_tun_inbound_peer_relay_summary(
    *,
    packet: bytes,
    owner_by_ipv4: dict[str, str],
    owner_by_ipv6: dict[str, str],
    peer_id_by_ref: dict[str, int],
    active_peer_bindings: list[dict[str, object]],
    source_peer_id: int,
) -> dict[str, object]:
    route = ChannelMux._shared_tun_plan_outbound_route(
        {
            "owner_by_ipv4": owner_by_ipv4,
            "owner_by_ipv6": owner_by_ipv6,
        },
        peer_id_by_ref,
        active_peer_bindings,
        packet,
    )
    selected_peer_ids = [int(v) for v in list(route.get("selected_peer_ids") or [])]
    if (
        str(route.get("route_class") or "") == "unicast"
        and bool(route.get("routed"))
        and selected_peer_ids
        and int(selected_peer_ids[0]) != int(source_peer_id)
    ):
        return {
            "relay_to_peer": True,
            "deliver_local": False,
            "route_class": route.get("route_class"),
            "selected_peer_ids": [int(v) for v in list(route.get("selected_peer_ids") or [])],
            "selected_chan_ids": [int(v) for v in list(route.get("selected_chan_ids") or [])],
            "ip_version": route.get("ip_version"),
            "destination_ip": route.get("destination_ip"),
            "drop_reason": route.get("drop_reason"),
        }
    return {
        "relay_to_peer": False,
        "deliver_local": True,
        "route_class": route.get("route_class"),
        "selected_peer_ids": [int(v) for v in list(route.get("selected_peer_ids") or [])],
        "selected_chan_ids": [int(v) for v in list(route.get("selected_chan_ids") or [])],
        "ip_version": route.get("ip_version"),
        "destination_ip": route.get("destination_ip"),
        "drop_reason": route.get("drop_reason"),
    }


def _python_scoped_tun_throttle_sequence_summary(
    sequence: list[dict[str, int | str]],
) -> list[dict[str, object]]:
    mux = ChannelMux(_FakeSession(connected=True), asyncio.new_event_loop())
    try:
        snapshots: list[dict[str, object]] = []
        for step in sequence:
            scope_key = (str(step["scope_id"]),)
            mux.session._metrics.waiting_count = int(step["buffered_frames"])
            allowed = mux._local_tun_send_allowed(
                int(step["packet_bytes"]),
                now_ns=int(step["now_ns"]),
                scope_key=scope_key,
            )
            state = mux._advance_tun_inflow_window(scope_key, int(step["now_ns"]))
            if allowed:
                mux._record_local_tun_forward(
                    int(step["packet_bytes"]),
                    now_ns=int(step["now_ns"]),
                    scope_key=scope_key,
                )
                state = mux._advance_tun_inflow_window(scope_key, int(step["now_ns"]))
            else:
                state["throttle_drop_count"] = int(state.get("throttle_drop_count", 0) or 0) + 1
            snapshots.append(
                {
                    "scope_id": str(step["scope_id"]),
                    "allowed": bool(allowed),
                    "prev_window_bytes": int(state.get("prev_bytes", 0) or 0),
                    "curr_window_bytes": int(state.get("curr_bytes", 0) or 0),
                    "throttle_drop_count": int(state.get("throttle_drop_count", 0) or 0),
                }
            )
        return snapshots
    finally:
        mux.loop.close()


def _shared_tun_test_spec() -> ChannelMux.ServiceSpec:
    return ChannelMux.ServiceSpec(
        2,
        "tun",
        "obtun1",
        1500,
        "tun",
        "obtun0",
        1500,
        options={
            "shared_tun_ownership": {
                "mode": "server_shared",
                "peers": [
                    {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"], "ipv6": ["fd20:107::2"]},
                    {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                ],
            }
        },
    )


def _python_shared_tun_peer_binding_sequence_summary() -> list[dict[str, object]]:
    mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
    try:
        svc_key = ("peer", 77, 2)
        mux._install_shared_tun_ownership_for_service(svc_key, _shared_tun_test_spec())
        mux._record_shared_tun_peer_binding(svc_key, 77, 11)
        mux._record_shared_tun_peer_binding(svc_key, 88, 22)
        mux._record_shared_tun_peer_binding(svc_key, 77, 13)
        mux._drop_shared_tun_peer_binding(svc_key, 77, 11)
        return [
            {
                "peer_id": int(key[1]),
                "preferred_chan_id": value.get("preferred_chan_id"),
                "bound_chan_ids": [int(v) for v in list(value.get("bound_chan_ids") or [])],
            }
            for key, value in sorted(mux._shared_tun_runtime_by_peer.items(), key=lambda item: int(item[0][1]))
        ]
    finally:
        mux.loop.close()


def _python_shared_tun_disconnect_cleanup_summary() -> dict[str, object]:
    mux = ChannelMux(_FakeSession(), asyncio.new_event_loop())
    try:
        svc_key = ("peer", 77, 2)
        spec = _shared_tun_test_spec()
        dev = ChannelMux.TunDevice(fd=44, ifname="obtun1", mtu=1500, service_key=svc_key)
        mux._install_shared_tun_ownership_for_service(svc_key, spec)
        mux._chan_owner_peer_id[11] = 77
        mux._chan_owner_peer_id[22] = 88
        mux._record_shared_tun_peer_binding(svc_key, 77, 11)
        mux._record_shared_tun_peer_binding(svc_key, 88, 22)
        allowed, _, reason = mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=11,
            packet=_ipv4_packet("192.168.107.2", "192.168.107.1"),
        )
        assert allowed and reason is None
        allowed, _, reason = mux._shared_tun_guard_inbound_packet(
            dev=dev,
            chan=22,
            packet=_ipv4_packet("192.168.107.4", "192.168.107.1"),
        )
        assert allowed and reason is None
        mux.on_peer_disconnected(77)
        mux.loop.run_until_complete(asyncio.sleep(0))
        active_peer_bindings = [
            {
                "peer_id": int(key[1]),
                "preferred_chan_id": value.get("preferred_chan_id"),
                "bound_chan_ids": [int(v) for v in list(value.get("bound_chan_ids") or [])],
            }
            for key, value in sorted(mux._shared_tun_runtime_by_peer.items(), key=lambda item: int(item[0][1]))
            if key[0] == svc_key
        ]
        peer_ref_by_peer = {
            str(key[1]): value
            for key, value in sorted(mux._shared_tun_peer_ref_by_peer.items(), key=lambda item: int(item[0][1]))
            if key[0] == svc_key
        }
        peer_id_by_ref = {
            str(key[1]): int(value)
            for key, value in sorted(mux._shared_tun_peer_id_by_ref.items(), key=lambda item: str(item[0][1]))
            if key[0] == svc_key
        }
        return {
            "active_peer_bindings": active_peer_bindings,
            "peer_ref_by_peer": peer_ref_by_peer,
            "peer_id_by_ref": peer_id_by_ref,
        }
    finally:
        mux.loop.close()


def test_swift_component_shared_tun_ownership_snapshot_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    spec = ChannelMux.ServiceSpec(
        svc_id=3,
        l_proto="tun",
        l_bind="obtun0",
        l_port=1500,
        r_proto="tun",
        r_host="obtun1",
        r_port=1500,
        name="shared-server-tun",
        options={
            "shared_tun_ownership": {
                "mode": "server_shared",
                "peers": [
                    {"peer_ref": "linux-client", "ipv4": ["192.168.107.2/32"], "ipv6": ["fd20:107::2/128"]},
                    {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                ],
            }
        },
    )
    python = ChannelMux._shared_tun_ownership_snapshot_for_spec(spec)
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "shared_tun_ownership_snapshot",
            "spec": {
                "svc_id": spec.svc_id,
                "l_proto": spec.l_proto,
                "l_bind": spec.l_bind,
                "l_port": spec.l_port,
                "r_proto": spec.r_proto,
                "r_host": spec.r_host,
                "r_port": spec.r_port,
                "name": spec.name,
                "lifecycle_hooks": spec.lifecycle_hooks,
                "options": spec.options,
            },
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_local_tun_packet_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    python = _python_channelmux_local_tun_packet_summary()
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_local_tun_packet",
            "packet_hex": "616263",
            "mtu": 1500,
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tun_id": 1,
            "spec": python["spec"],
        },
    )
    python.pop("spec")
    assert swift["snapshot"] == python


def test_swift_component_normalizes_local_shared_tun_ipv4_source(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("172.20.10.4", "1.1.1.1")
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "normalize_local_tun_packet_source",
            "packet_hex": packet.hex(),
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "local_tunnel_address": "192.168.106.3",
        },
    )
    normalized = bytes.fromhex(swift["normalized_packet_hex"])
    assert normalized[12:16] == b"\xc0\xa8\x6a\x03"
    assert normalized[16:20] == b"\x01\x01\x01\x01"


def test_swift_component_normalizes_local_shared_tun_ipv6_source(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv6_packet("2409:1111::4", "2606:4700:4700::1111")
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "normalize_local_tun_packet_source",
            "packet_hex": packet.hex(),
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "local_tunnel_address6": "fd20:106::3",
        },
    )
    normalized = bytes.fromhex(swift["normalized_packet_hex"])
    assert normalized[8:24] == bytes.fromhex("fd200106000000000000000000000003")
    assert normalized[24:40] == bytes.fromhex("26064700470000000000000000001111")


def test_swift_component_tun_open_then_local_packet_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    python = _python_channelmux_tun_open_then_local_packet_summary()
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_tun_open_then_local_packet",
            "open_chan_id": 7,
            "open_payload_hex": python["open_payload_hex"],
            "packet_hex": "616263",
            "mtu": 1600,
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tun_id": 1,
            "spec": python["local_spec"],
        },
    )
    python.pop("local_spec")
    python.pop("open_payload_hex")
    assert swift == python


def test_swift_component_inbound_tun_fragment_sequence_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    python = _python_channelmux_inbound_tun_fragment_sequence_summary()
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_inbound_tun_fragment_sequence",
            "chan_id": 7,
            "fragments_hex": python["fragments_hex"],
            "mtu": 200,
            "bound_chan_id": 7,
        },
    )
    python.pop("fragments_hex")
    assert swift == python


def test_swift_component_tun_close_then_local_packet_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    python = _python_channelmux_tun_close_then_local_packet_summary()
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_tun_close_then_local_packet",
            "open_chan_id": 7,
            "open_payload_hex": python["open_payload_hex"],
            "packet_hex": "616263",
            "mtu": 1600,
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tun_id": 1,
            "spec": python["local_spec"],
        },
    )
    python.pop("local_spec")
    python.pop("open_payload_hex")
    assert swift == python


def test_swift_component_guarded_inbound_tun_data_accepts_owned_ipv4(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.2", "192.168.107.1")
    python = _python_guarded_inbound_tun_data_summary(
        packet=packet,
        allowed_source_ips={"192.168.107.2", "fd20:107::2"},
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_inbound_tun_data_guarded",
            "chan_id": 7,
            "body_hex": packet.hex(),
            "mtu": 1500,
            "bound_chan_id": 7,
            "allowed_source_ips": ["192.168.107.2", "fd20:107::2"],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_guarded_inbound_tun_data_rejects_spoofed_ipv4(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.9", "192.168.107.1")
    python = _python_guarded_inbound_tun_data_summary(
        packet=packet,
        allowed_source_ips={"192.168.107.2", "fd20:107::2"},
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_inbound_tun_data_guarded",
            "chan_id": 7,
            "body_hex": packet.hex(),
            "mtu": 1500,
            "bound_chan_id": 7,
            "allowed_source_ips": ["192.168.107.2", "fd20:107::2"],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_guarded_inbound_tun_data_accepts_broadcast_destination(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.2", "255.255.255.255")
    python = _python_guarded_inbound_tun_data_summary(
        packet=packet,
        allowed_source_ips={"192.168.107.2", "fd20:107::2"},
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_inbound_tun_data_guarded",
            "chan_id": 7,
            "body_hex": packet.hex(),
            "mtu": 1500,
            "bound_chan_id": 7,
            "allowed_source_ips": ["192.168.107.2", "fd20:107::2"],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_guarded_inbound_tun_data_accepts_owned_ipv6(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv6_packet("fd20:107::2", "fd20:107::1")
    python = _python_guarded_inbound_tun_data_summary(
        packet=packet,
        allowed_source_ips={"192.168.107.2", "fd20:107::2"},
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_inbound_tun_data_guarded",
            "chan_id": 7,
            "body_hex": packet.hex(),
            "mtu": 1500,
            "bound_chan_id": 7,
            "allowed_source_ips": ["192.168.107.2", "fd20:107::2"],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_guarded_inbound_tun_data_rejects_malformed_packet(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = b"\x45\x00"
    python = _python_guarded_inbound_tun_data_summary(
        packet=packet,
        allowed_source_ips={"192.168.107.2", "fd20:107::2"},
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_inbound_tun_data_guarded",
            "chan_id": 7,
            "body_hex": packet.hex(),
            "mtu": 1500,
            "bound_chan_id": 7,
            "allowed_source_ips": ["192.168.107.2", "fd20:107::2"],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_outbound_route_unicast_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.1", "192.168.107.4")
    python = _python_shared_tun_outbound_route_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
        owner_by_ipv6={},
        peer_id_by_ref={"linux-client": 77, "ios-client": 88},
        active_peer_bindings=[
            {"peer_id": 77, "preferred_chan_id": 11},
            {"peer_id": 88, "preferred_chan_id": 22},
        ],
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_outbound_route",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {"linux-client": 77, "ios-client": 88},
            "active_peer_bindings": [
                {"peer_id": 77, "preferred_chan_id": 11},
                {"peer_id": 88, "preferred_chan_id": 22},
            ],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_outbound_route_broadcast_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.1", "255.255.255.255")
    python = _python_shared_tun_outbound_route_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
        owner_by_ipv6={},
        peer_id_by_ref={"linux-client": 77, "ios-client": 88},
        active_peer_bindings=[
            {"peer_id": 88, "preferred_chan_id": 22},
            {"peer_id": 77, "preferred_chan_id": 11},
        ],
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_outbound_route",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {"linux-client": 77, "ios-client": 88},
            "active_peer_bindings": [
                {"peer_id": 88, "preferred_chan_id": 22},
                {"peer_id": 77, "preferred_chan_id": 11},
            ],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_outbound_route_unknown_destination_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.1", "192.168.107.9")
    python = _python_shared_tun_outbound_route_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client"},
        owner_by_ipv6={},
        peer_id_by_ref={"linux-client": 77},
        active_peer_bindings=[{"peer_id": 77, "preferred_chan_id": 11}],
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_outbound_route",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {"linux-client": 77},
            "active_peer_bindings": [{"peer_id": 77, "preferred_chan_id": 11}],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_outbound_route_inactive_destination_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.1", "192.168.107.2")
    python = _python_shared_tun_outbound_route_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client"},
        owner_by_ipv6={},
        peer_id_by_ref={"linux-client": 77},
        active_peer_bindings=[{"peer_id": 77, "preferred_chan_id": None}],
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_outbound_route",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {"linux-client": 77},
            "active_peer_bindings": [{"peer_id": 77, "preferred_chan_id": None}],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_inbound_peer_relay_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.2", "192.168.107.4")
    python = _python_shared_tun_inbound_peer_relay_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
        owner_by_ipv6={},
        peer_id_by_ref={"linux-client": 77, "ios-client": 88},
        active_peer_bindings=[
            {"peer_id": 77, "preferred_chan_id": 11},
            {"peer_id": 88, "preferred_chan_id": 22},
        ],
        source_peer_id=77,
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_inbound_peer_relay",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {"linux-client": 77, "ios-client": 88},
            "active_peer_bindings": [
                {"peer_id": 77, "preferred_chan_id": 11},
                {"peer_id": 88, "preferred_chan_id": 22},
            ],
            "source_peer_id": 77,
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_inbound_peer_relay_avoids_self_loop(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.2", "192.168.107.2")
    python = _python_shared_tun_inbound_peer_relay_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
        owner_by_ipv6={},
        peer_id_by_ref={"linux-client": 77, "ios-client": 88},
        active_peer_bindings=[
            {"peer_id": 77, "preferred_chan_id": 11},
            {"peer_id": 88, "preferred_chan_id": 22},
        ],
        source_peer_id=77,
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_inbound_peer_relay",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client", "192.168.107.4": "ios-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {"linux-client": 77, "ios-client": 88},
            "active_peer_bindings": [
                {"peer_id": 77, "preferred_chan_id": 11},
                {"peer_id": 88, "preferred_chan_id": 22},
            ],
            "source_peer_id": 77,
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_scoped_tun_throttle_sequence_preserves_unrelated_scope_budget(
    swift_channelmux_component_runner: Path,
) -> None:
    sequence = [
        {"scope_id": "peer-a", "packet_bytes": 100, "buffered_frames": 0, "now_ns": 0},
        {"scope_id": "peer-b", "packet_bytes": 90, "buffered_frames": 0, "now_ns": 0},
        {"scope_id": "peer-a", "packet_bytes": 80, "buffered_frames": 1, "now_ns": 100_000_000},
        {"scope_id": "peer-a", "packet_bytes": 20, "buffered_frames": 1, "now_ns": 100_000_000},
        {"scope_id": "peer-b", "packet_bytes": 80, "buffered_frames": 1, "now_ns": 100_000_000},
    ]
    python = _python_scoped_tun_throttle_sequence_summary(sequence)
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_scoped_tun_throttle_sequence",
            "scope_ids": [str(step["scope_id"]) for step in sequence],
            "packet_bytes_sequence": [int(step["packet_bytes"]) for step in sequence],
            "buffered_frames_sequence": [int(step["buffered_frames"]) for step in sequence],
            "now_ns_sequence": [int(step["now_ns"]) for step in sequence],
        },
    )
    assert swift["snapshots"] == python


def test_swift_component_shared_tun_scope_ids_preserve_broadcast_unicast_isolation(
    swift_channelmux_component_runner: Path,
) -> None:
    sequence = [
        {
            "scope_id": "shared:local:0:5:broadcast:peers=77,88:chans=11,22",
            "packet_bytes": 120,
            "buffered_frames": 0,
            "now_ns": 0,
        },
        {
            "scope_id": "shared:local:0:5:broadcast:peers=77,88:chans=11,22",
            "packet_bytes": 120,
            "buffered_frames": 1,
            "now_ns": 100_000_000,
        },
        {
            "scope_id": "shared:local:0:5:unicast:peers=77:chans=11",
            "packet_bytes": 120,
            "buffered_frames": 0,
            "now_ns": 200_000_000,
        },
        {
            "scope_id": "shared:local:0:5:unicast:peers=77:chans=11",
            "packet_bytes": 100,
            "buffered_frames": 1,
            "now_ns": 300_000_000,
        },
    ]
    python = _python_scoped_tun_throttle_sequence_summary(sequence)
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "drive_channelmux_scoped_tun_throttle_sequence",
            "scope_ids": [str(step["scope_id"]) for step in sequence],
            "packet_bytes_sequence": [int(step["packet_bytes"]) for step in sequence],
            "buffered_frames_sequence": [int(step["buffered_frames"]) for step in sequence],
            "now_ns_sequence": [int(step["now_ns"]) for step in sequence],
        },
    )
    assert swift["snapshots"] == python


def test_swift_component_shared_tun_outbound_route_unmapped_destination_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    packet = _ipv4_packet("192.168.107.1", "192.168.107.2")
    python = _python_shared_tun_outbound_route_summary(
        packet=packet,
        owner_by_ipv4={"192.168.107.2": "linux-client"},
        owner_by_ipv6={},
        peer_id_by_ref={},
        active_peer_bindings=[],
    )
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "plan_shared_tun_outbound_route",
            "body_hex": packet.hex(),
            "owner_by_ipv4": {"192.168.107.2": "linux-client"},
            "owner_by_ipv6": {},
            "peer_id_by_ref": {},
            "active_peer_bindings": [],
        },
    )
    assert swift["snapshot"] == python


def test_swift_component_shared_tun_peer_binding_sequence_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    python = _python_shared_tun_peer_binding_sequence_summary()
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "apply_shared_tun_peer_binding_sequence",
            "operations": [
                {"peer_id": 77, "chan_id": 11, "drop": False},
                {"peer_id": 88, "chan_id": 22, "drop": False},
                {"peer_id": 77, "chan_id": 13, "drop": False},
                {"peer_id": 77, "chan_id": 11, "drop": True},
            ],
        },
    )
    assert swift["snapshots"] == python


def test_swift_component_shared_tun_disconnect_cleanup_matches_python(
    swift_channelmux_component_runner: Path,
) -> None:
    python = _python_shared_tun_disconnect_cleanup_summary()
    swift = _run_swift_component(
        swift_channelmux_component_runner,
        {
            "action": "cleanup_shared_tun_peer_state_on_disconnect",
            "active_peer_bindings": [
                {"peer_id": 77, "preferred_chan_id": 11, "bound_chan_ids": [11]},
                {"peer_id": 88, "preferred_chan_id": 22, "bound_chan_ids": [22]},
            ],
            "peer_ref_by_peer": {"77": "linux-client", "88": "ios-client"},
            "peer_id_by_ref": {"linux-client": 77, "ios-client": 88},
            "disconnected_peer_id": 77,
        },
    )
    assert swift["snapshot"] == python
