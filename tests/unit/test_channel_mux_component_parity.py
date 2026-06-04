from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from obstacle_bridge.bridge import ChannelMux
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
