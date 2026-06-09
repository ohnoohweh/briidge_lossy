from __future__ import annotations

import asyncio
import argparse
import contextlib
import json
import shutil
import struct
import subprocess
import zlib
from unittest import mock
from pathlib import Path

import pytest

from obstacle_bridge.bridge import ChannelMux, SessionMetrics
from obstacle_bridge.bridge import BaseFrameV2, ControlPacket, DataPacket, Protocol, Session
from obstacle_bridge.bridge import FRAME_CONT, FRAME_FIRST
from obstacle_bridge.bridge import Runner, TcpStreamSession, UdpSession, QuicSession, WebSocketSession, SecureLinkPskSession
from obstacle_bridge.bridge_compression import CompressLayerSession
import obstacle_bridge.bridge_transport_udp as myudp
from tests.unit import test_ws_payload_mode as ws_test_fixtures


ROOT = Path(__file__).resolve().parents[2]
SWIFT_CODEC_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeChannelMuxCodec.swift"
SWIFT_SECURELINK_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeSecureLinkPskCodec.swift"
SWIFT_UDP_CODEC_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeUdpOverlayCodec.swift"
SWIFT_UDP_SESSION_CODEC_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeUdpOverlaySessionCodec.swift"
SWIFT_UDP_PEER_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeUdpOverlayPeerRuntime.swift"
SWIFT_CHANNELMUX_TUN_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeChannelMuxTunRuntime.swift"
SWIFT_CHANNELMUX_UDP_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeChannelMuxUdpRuntime.swift"
SWIFT_CHANNELMUX_TCP_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeChannelMuxTcpRuntime.swift"
SWIFT_COMPRESS_LAYER_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeCompressLayerRuntime.swift"
SWIFT_OVERLAY_STACK_PLANNER_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeOverlayStackPlanner.swift"
SWIFT_WS_PAYLOAD_CODEC_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeWebSocketPayloadCodec.swift"
SWIFT_WS_OVERLAY_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeWebSocketOverlayRuntime.swift"
SWIFT_TCP_OVERLAY_RUNTIME_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeTcpOverlayRuntime.swift"
SWIFT_RUNNER_SOURCE = ROOT / "tests" / "fixtures" / "channelmux_codec_runner.swift"


class _FakeSession:
    def __init__(
        self,
        *,
        connected: bool = False,
        max_app_payload_size: int = 65535,
        waiting_count: int = 0,
    ) -> None:
        self.app_cb = None
        self.peer_disconnect_cb = None
        self.connected = connected
        self.max_app_payload_size = max_app_payload_size
        self.sent: list[bytes] = []
        self._metrics = SessionMetrics(waiting_count=waiting_count)

    def is_connected(self):
        return self.connected

    def get_max_app_payload_size(self):
        return self.max_app_payload_size

    def set_on_app_payload(self, cb):
        self.app_cb = cb

    def set_on_peer_disconnect(self, cb):
        self.peer_disconnect_cb = cb

    def send_app(self, payload, *args, **kwargs):
        self.sent.append(bytes(payload))
        return len(payload)

    def get_metrics(self):
        return self._metrics


class _FakeCompressInnerSession:
    def __init__(self, *, max_payload=4096):
        self._max_payload = int(max_payload)
        self.sent = []

    async def start(self):
        return None

    async def stop(self):
        return None

    async def wait_connected(self, timeout=None):
        return True

    def is_connected(self):
        return True

    def send_app(self, payload: bytes, peer_id=None):
        self.sent.append((bytes(payload), peer_id))
        return len(payload)

    def get_max_app_payload_size(self):
        return self._max_payload

    def get_metrics(self):
        return None

    def set_on_app_payload(self, cb):
        self._on_app = cb

    def set_on_state_change(self, cb):
        self._on_state = cb

    def set_on_peer_rx(self, cb):
        self._on_peer_rx = cb

    def set_on_peer_tx(self, cb):
        self._on_peer_tx = cb

    def set_on_peer_set(self, cb):
        self._on_peer_set = cb

    def set_on_peer_disconnect(self, cb):
        self._on_peer_disconnect = cb

    def set_on_app_from_peer_bytes(self, cb):
        self._on_app_from_peer_bytes = cb

    def set_on_transport_epoch_change(self, cb):
        self._on_transport_epoch_change = cb


@pytest.fixture(scope="session")
def swift_channelmux_runner(tmp_path_factory: pytest.TempPathFactory) -> Path:
    swiftc = shutil.which("swiftc")
    if swiftc is None:
        pytest.skip("swiftc is required for Swift parity tests")
    output_dir = tmp_path_factory.mktemp("swift_channelmux")
    binary = output_dir / "channelmux_codec_runner"
    command = [
        swiftc,
        "-o",
        str(binary),
        str(SWIFT_CODEC_SOURCE),
        str(SWIFT_SECURELINK_SOURCE),
        str(SWIFT_UDP_CODEC_SOURCE),
        str(SWIFT_UDP_SESSION_CODEC_SOURCE),
        str(SWIFT_UDP_PEER_RUNTIME_SOURCE),
        str(SWIFT_CHANNELMUX_TUN_RUNTIME_SOURCE),
        str(SWIFT_CHANNELMUX_UDP_RUNTIME_SOURCE),
        str(SWIFT_CHANNELMUX_TCP_RUNTIME_SOURCE),
        str(SWIFT_COMPRESS_LAYER_RUNTIME_SOURCE),
        str(SWIFT_OVERLAY_STACK_PLANNER_SOURCE),
        str(SWIFT_WS_PAYLOAD_CODEC_SOURCE),
        str(SWIFT_WS_OVERLAY_RUNTIME_SOURCE),
        str(SWIFT_TCP_OVERLAY_RUNTIME_SOURCE),
        str(SWIFT_RUNNER_SOURCE),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"failed to compile Swift ChannelMux parity runner\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return binary


def _run_swift(binary: Path, request: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        [str(binary)],
        input=json.dumps(request),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Swift runner failed\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def _make_mux(*, connected: bool = False, max_app_payload_size: int = 65535) -> ChannelMux:
    mux = ChannelMux(
        _FakeSession(connected=connected, max_app_payload_size=max_app_payload_size),
        asyncio.new_event_loop(),
    )
    mux._mux_instance_id = 0x1122334455667788
    mux._mux_connection_seq = 0x10203040
    return mux


def _close_mux(mux: ChannelMux) -> None:
    mux.loop.close()


def _compress_args(**overrides) -> argparse.Namespace:
    base = dict(
        compress_layer=True,
        compress_layer_algo="zlib",
        compress_layer_level=3,
        compress_layer_min_bytes=64,
        compress_layer_types="data,data_frag",
        peer="",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _compress_pack_mux(mtype: int, data: bytes, *, chan: int = 7, proto: int = 1, counter: int = 2) -> bytes:
    return CompressLayerSession._MUX_HDR.pack(int(chan), int(proto), int(counter), int(mtype), len(data)) + bytes(data)


def _compress_unpack_mux(payload: bytes) -> tuple[int, int, int, int, bytes]:
    chan, proto, counter, mtype, dlen = CompressLayerSession._MUX_HDR.unpack(payload[: CompressLayerSession._MUX_HDR.size])
    return chan, proto, counter, mtype, payload[CompressLayerSession._MUX_HDR.size : CompressLayerSession._MUX_HDR.size + dlen]


def _make_compress_wrapper(*, max_payload: int = 4096, **args_overrides) -> tuple[CompressLayerSession, _FakeCompressInnerSession]:
    inner = _FakeCompressInnerSession(max_payload=max_payload)
    wrapper = CompressLayerSession(inner, _compress_args(**args_overrides), "tcp")
    return wrapper, inner


def _python_compress_roundtrip_profitable_summary() -> dict[str, object]:
    wrapper, inner = _make_compress_wrapper(compress_layer_min_bytes=1)
    payload = _compress_pack_mux(0x00, b"A" * 512)
    delivered = []
    wrapper.set_on_app_payload(lambda p, peer_id=None: delivered.append((bytes(p), peer_id)))
    sent_bytes = wrapper.send_app(payload)
    sent_payload, sent_peer_id = inner.sent[0]
    _chan, _proto, _counter, sent_mtype, sent_body = _compress_unpack_mux(sent_payload)
    wrapper._on_inner_payload(sent_payload, peer_id=11)
    restored_payload, restored_peer_id = delivered[0]
    return {
        "sent_bytes": sent_bytes,
        "sent_payload_hex": sent_payload.hex(),
        "sent_peer_id": sent_peer_id,
        "sent_mtype": sent_mtype,
        "sent_body_len": len(sent_body),
        "restored_payload_hex": restored_payload.hex(),
        "restored_peer_id": restored_peer_id,
        "status": wrapper.get_compress_layer_status_snapshot(),
        "peer_status": wrapper.get_compress_layer_status_snapshot(peer_id=11),
    }


def _python_compress_client_peer_snapshot_summary() -> dict[str, object]:
    wrapper, _inner = _make_compress_wrapper(peer="127.0.0.1", compress_layer=True)
    return wrapper.get_compress_layer_status_snapshot(peer_id=0)


def _python_compress_send_no_gain_summary() -> dict[str, object]:
    wrapper, inner = _make_compress_wrapper(compress_layer_min_bytes=1)
    payload = _compress_pack_mux(0x00, bytes(range(256)))
    sent_bytes = wrapper.send_app(payload)
    sent_payload, sent_peer_id = inner.sent[0]
    _chan, _proto, _counter, sent_mtype, sent_body = _compress_unpack_mux(sent_payload)
    return {
        "sent_bytes": sent_bytes,
        "sent_payload_hex": sent_payload.hex(),
        "sent_peer_id": sent_peer_id,
        "sent_mtype": sent_mtype,
        "sent_body_hex": sent_body.hex(),
        "status": wrapper.get_compress_layer_status_snapshot(),
    }


def _python_compress_invalid_rx_summary() -> dict[str, object]:
    wrapper, _inner = _make_compress_wrapper()
    delivered = []
    wrapper.set_on_app_payload(lambda p, peer_id=None: delivered.append((bytes(p), peer_id)))
    wrapper._on_inner_payload(_compress_pack_mux(0x80, b"not-zlib"), peer_id=2)
    return {
        "delivered": [[payload.hex(), peer_id] for payload, peer_id in delivered],
        "status": wrapper.get_compress_layer_status_snapshot(),
        "peer_status": wrapper.get_compress_layer_status_snapshot(peer_id=2),
    }


def _python_compress_oversize_rx_summary() -> dict[str, object]:
    wrapper, _inner = _make_compress_wrapper(max_payload=80)
    delivered = []
    wrapper.set_on_app_payload(lambda p, peer_id=None: delivered.append((bytes(p), peer_id)))
    wrapper._on_inner_payload(_compress_pack_mux(0x80, zlib.compress(b"B" * 500, 3)), peer_id=3)
    return {
        "delivered": [[payload.hex(), peer_id] for payload, peer_id in delivered],
        "status": wrapper.get_compress_layer_status_snapshot(),
        "peer_status": wrapper.get_compress_layer_status_snapshot(peer_id=3),
    }


def _python_compress_server_activation_summary() -> dict[str, object]:
    wrapper, inner = _make_compress_wrapper(
        compress_layer=False,
        compress_layer_min_bytes=4096,
        compress_layer_level=1,
        compress_layer_types="data",
    )
    payload = _compress_pack_mux(0x00, b"C" * 512)
    peer_id = 44
    delivered = []
    wrapper.set_on_app_payload(lambda p, peer_id=None: delivered.append((bytes(p), peer_id)))

    before_enabled = wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)["enabled"]
    before_sent_bytes = wrapper.send_app(payload, peer_id=peer_id)
    before_payload, before_peer_id = inner.sent[-1]
    _chan, _proto, _counter, before_mtype, _body = _compress_unpack_mux(before_payload)

    wrapper._on_inner_payload(_compress_pack_mux(0x80, zlib.compress(b"D" * 512, 9)), peer_id=peer_id)
    peer_status = wrapper.get_compress_layer_status_snapshot(peer_id=peer_id)

    after_sent_bytes = wrapper.send_app(payload, peer_id=peer_id)
    after_payload, after_peer_id = inner.sent[-1]
    _chan, _proto, _counter, after_mtype, _body = _compress_unpack_mux(after_payload)

    routed_sent_bytes = wrapper.send_app(payload)
    routed_payload, routed_peer_id = inner.sent[-1]
    _chan, _proto, _counter, routed_mtype, _body = _compress_unpack_mux(routed_payload)

    return {
        "before_enabled": before_enabled,
        "before_sent_bytes": before_sent_bytes,
        "before_payload_hex": before_payload.hex(),
        "before_peer_id": before_peer_id,
        "before_mtype": before_mtype,
        "delivered": [[payload.hex(), deliver_peer_id] for payload, deliver_peer_id in delivered],
        "peer_status": peer_status,
        "after_sent_bytes": after_sent_bytes,
        "after_payload_hex": after_payload.hex(),
        "after_peer_id": after_peer_id,
        "after_mtype": after_mtype,
        "routed_sent_bytes": routed_sent_bytes,
        "routed_payload_hex": routed_payload.hex(),
        "routed_peer_id": routed_peer_id,
        "routed_mtype": routed_mtype,
        "status": wrapper.get_compress_layer_status_snapshot(),
    }


def _overlay_args(**overrides) -> argparse.Namespace:
    base = dict(
        overlay_transport="myudp",
        tcp_bind="::",
        udp_own_port=4433,
        udp_peer=None,
        udp_peer_port=443,
        tcp_own_port=8081,
        tcp_peer=None,
        tcp_peer_port=443,
        quic_own_port=443,
        quic_peer=None,
        quic_peer_port=443,
        ws_own_port=8080,
        ws_peer=None,
        ws_peer_port=443,
        overlay_port_myudp=None,
        overlay_port_tcp=None,
        overlay_port_quic=None,
        overlay_port_ws=None,
        secure_link=False,
        secure_link_mode="off",
        secure_link_psk="",
        secure_link_require=False,
        secure_link_rekey_after_frames=0,
        secure_link_root_pub="",
        secure_link_cert_body="",
        secure_link_cert_sig="",
        secure_link_private_key="",
        secure_link_revoked_serials="",
        secure_link_cert_reload_on_restart=True,
        compress_layer=True,
        compress_layer_algo="zlib",
        compress_layer_level=3,
        compress_layer_min_bytes=64,
        compress_layer_types="data,data_frag",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _overlay_chain_labels(session, secure_link_mode: str, transport: str) -> list[str]:
    labels = []
    current = session
    while True:
        if isinstance(current, CompressLayerSession):
            labels.append("compress_layer")
            current = current._inner
            continue
        if isinstance(current, SecureLinkPskSession):
            labels.append(f"secure_link_{secure_link_mode}")
            current = current._inner
            continue
        labels.append(transport)
        return labels


def _transport_factory_class(transport: str):
    return {
        "myudp": UdpSession,
        "tcp": TcpStreamSession,
        "quic": QuicSession,
        "ws": WebSocketSession,
    }[transport]


def _python_overlay_parse_summary(raw: str, **arg_overrides) -> dict[str, object]:
    try:
        return {
            "ok": True,
            "transports": Runner._parse_overlay_transports(_overlay_args(overlay_transport=raw, **arg_overrides)),
        }
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}


def _python_overlay_stack_plan_summary(*, transport: str, **arg_overrides) -> dict[str, object]:
    args = _overlay_args(overlay_transport=transport, **arg_overrides)
    factory_class = _transport_factory_class(transport)
    captured_args = []

    def _build(session_args):
        captured_args.append(session_args)
        return _FakeSession()

    try:
        with mock.patch.object(factory_class, "from_args", side_effect=_build):
            sessions = Runner.build_sessions_from_overlay(args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    top = sessions[0][1]
    chain = _overlay_chain_labels(
        top,
        str(getattr(args, "secure_link_mode", "off") or "off").strip().lower(),
        transport,
    )
    compress_top = top if isinstance(top, CompressLayerSession) else None
    return {
        "ok": True,
        "transport": sessions[0][0],
        "peer_host": getattr(captured_args[0], "peer", None),
        "secure_link_mode": (
            str(getattr(args, "secure_link_mode", "off") or "off").strip().lower()
            if any(label.startswith("secure_link_") for label in chain)
            else None
        ),
        "compress_wrapped": "compress_layer" in chain,
        "compress_configured_enabled": bool(getattr(args, "compress_layer", True)),
        "compress_runtime_enabled": (
            compress_top.get_compress_layer_status_snapshot()["enabled"] if compress_top is not None else None
        ),
        "layers_top_down": chain,
    }


def _ws_payload_args(mode: str, *, max_size: int = 65535) -> argparse.Namespace:
    return argparse.Namespace(
        ws_bind="0.0.0.0",
        ws_own_port=0,
        ws_peer=None,
        ws_peer_port=0,
        ws_path="/",
        ws_subprotocol=None,
        ws_tls=False,
        ws_max_size=max_size,
        ws_payload_mode=mode,
        ws_static_dir="",
        ws_send_timeout=3.0,
        ws_tcp_user_timeout_ms=10000,
        ws_reconnect_grace=3.0,
        ws_proxy_mode="off",
        ws_proxy_host="",
        ws_proxy_port=8080,
        ws_proxy_auth="none",
    )


def _python_ws_payload_codec_summary(
    mode: str,
    *,
    wire: bytes | None = None,
    decode_message: str | bytes | None = None,
    max_size: int = 65535,
) -> dict[str, object]:
    session = WebSocketSession(_ws_payload_args(mode, max_size=max_size))
    payload_codec = session._ws_payload_codec
    encoded_kind = None
    encoded_value = None
    if wire is not None:
        encoded = payload_codec.encode(wire)
        if isinstance(encoded, (bytes, bytearray)):
            encoded_kind = "binary"
            encoded_value = bytes(encoded).hex()
        else:
            encoded_kind = "text"
            encoded_value = str(encoded)
    target_message = decode_message
    if target_message is None and wire is not None:
        target_message = payload_codec.encode(wire)
    decoded = None if target_message is None else session._decode_ws_message(target_message)
    return {
        "mode": mode,
        "encoded_kind": encoded_kind,
        "encoded_value": encoded_value,
        "decoded_hex": None if decoded is None else decoded.hex(),
        "frame_max_size": session._ws_frame_max_size,
        "max_encoded_size": payload_codec.max_encoded_size(0 if wire is None else len(wire)),
    }


def _python_ws_runtime_tx_summary(*, timeout: bool = False) -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = ws_test_fixtures._args("binary")
        if timeout:
            args.ws_send_timeout = 0.01
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        sent_sizes = []
        session.set_on_peer_tx(sent_sizes.append)
        session._ws = ws_test_fixtures._HangingWs() if timeout else ws_test_fixtures._FakeWs()

        session.send_app(b"hello")
        if timeout:
            await asyncio.sleep(0.05)
        await asyncio.wait_for(session._tx_queue.join(), timeout=1.0)

        snapshot = {
            "tx_bytes": session._tx_bytes,
            "peer_tx": sent_sizes,
            "sent_payload_kind": (
                "binary" if not timeout else None
            ),
            "sent_payload_value": (
                session._ws.sent[0].hex() if (not timeout and session._ws.sent) else None
            ),
            "close_calls": session._ws.close_calls,
            "early_buf_bytes": session._early_buf_bytes,
        }
        session._tx_task.cancel()
        await session._tx_task
        return snapshot

    return asyncio.run(_run())


def _python_ws_runtime_control_frame_summary() -> dict[str, object]:
    session = WebSocketSession(ws_test_fixtures._args("binary"))
    tx_ns = 123456789
    echo_ns = 987654321
    ping_wire = bytes([session._K_PING]) + struct.pack(">QQ", tx_ns, echo_ns)
    pong_wire = bytes([session._K_PONG]) + struct.pack(">Q", tx_ns)
    return {
        "decoded_ping": {
            "kind": "ping",
            "tx_ns": struct.unpack(">Q", ping_wire[1:9])[0],
            "echo_ns": struct.unpack(">Q", ping_wire[9:17])[0],
        },
        "decoded_pong": {
            "kind": "pong",
            "echo_tx_ns": struct.unpack(">Q", pong_wire[1:9])[0],
        },
        "encoded_pong_kind": "binary",
        "encoded_pong_value": pong_wire.hex(),
    }


def _python_ws_runtime_socket_config_summary() -> dict[str, object]:
    session = WebSocketSession(ws_test_fixtures._args("binary"))
    sock = ws_test_fixtures._FakeSocket()
    session._configure_ws_socket(ws_test_fixtures._SockoptWs(sock))
    tcp_user_timeout = getattr(__import__("socket"), "TCP_USER_TIMEOUT", None)
    return {
        "keepalive_enabled": ( __import__("socket").SOL_SOCKET, __import__("socket").SO_KEEPALIVE, 1) in sock.calls,
        "tcp_user_timeout_ms": 10000 if tcp_user_timeout is not None else None,
    }


def _python_ws_runtime_disconnect_summary(*, grace: float, reconnect: bool) -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = ws_test_fixtures._args("binary")
        args.ws_reconnect_grace = grace
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._overlay_connected = True
        session._schedule_overlay_disconnect()
        scheduled_before = session._disconnect_task is not None
        if reconnect:
            session._ws = object()
            await session._on_accept(ws_test_fixtures._SockoptWs(ws_test_fixtures._FakeSocket()))
            await asyncio.sleep(max(0.08, grace + 0.03))
            snapshot = {
                "scheduled_before": scheduled_before,
                "overlay_connected": session._overlay_connected,
                "disconnect_scheduled": session._disconnect_task is not None,
            }
            session._rx_task.cancel()
            await session._rx_task
            session._tx_task.cancel()
            await session._tx_task
            return snapshot
        await asyncio.sleep(max(0.08, grace + 0.03) if grace > 0 else 0)
        return {
            "scheduled_before": scheduled_before,
            "overlay_connected": session._overlay_connected,
            "disconnect_scheduled": session._disconnect_task is not None,
        }

    return asyncio.run(_run())


def _python_ws_runtime_http_preflight_summary(*, status_line: bytes, headers: list[bytes], body: bytes, host_header: str) -> dict[str, object]:
    async def _run() -> dict[str, object]:
        session = WebSocketSession(ws_test_fixtures._args("binary"))
        reader = ws_test_fixtures._FakeReader([status_line, *headers, b"\r\n"], body=body)
        writer = ws_test_fixtures._FakeWriter()
        try:
            with mock.patch("obstacle_bridge.bridge.asyncio.open_connection", mock.AsyncMock(return_value=(reader, writer))):
                await session._load_default_http_page(host="127.0.0.1", port=54321, host_header=host_header)
            return {
                "ok": True,
                "request": writer.buffer.decode("ascii"),
                "status_code": int(status_line.decode("ascii").split()[1]),
                "body_bytes": len(body),
            }
        except Exception as exc:
            return {
                "ok": False,
                "request": writer.buffer.decode("ascii"),
                "error": str(exc),
            }

    return asyncio.run(_run())


def _python_ws_runtime_connect_plan_summary(*, mode: str, proxy_active: bool = False) -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = ws_test_fixtures._args(mode)
        args.peer = "127.0.0.1"
        args.peer_port = 54321
        if proxy_active:
            args.ws_proxy_mode = "manual"
            args.ws_proxy_host = "proxy.example"
            args.ws_proxy_port = 8080
        session = WebSocketSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._peer_tuple = ("127.0.0.1", 54321)
        session._peer_name_host = "overlay.example"
        session._peer_name_port = 54321
        fake_ws = types.SimpleNamespace(local_address=("127.0.0.1", 40000), remote_address=("127.0.0.1", 54321))
        seen = {}

        async def fake_connect(uri, ssl=None, subprotocols=None, max_size=None, compression=None, ping_interval=None, ping_timeout=None, additional_headers=None, **kwargs):
            seen["uri"] = uri
            seen["subprotocols"] = subprotocols
            seen["max_size"] = max_size
            seen["compression"] = compression
            seen["additional_headers"] = additional_headers
            seen["kwargs"] = kwargs
            return fake_ws

        fake_websockets = types.SimpleNamespace(connect=fake_connect)
        with mock.patch.dict(sys.modules, {"websockets": fake_websockets}):
            with mock.patch.object(session, "_load_default_http_page", mock.AsyncMock()) as preflight:
                with mock.patch.object(session, "_on_accept", mock.AsyncMock()) as on_accept:
                    if proxy_active:
                        with mock.patch.object(session, "_open_ws_proxy_socket", mock.AsyncMock(return_value=mock.Mock())):
                            with mock.patch.object(session, "_get_ws_proxy_endpoint", return_value=("proxy.example", 8080)):
                                await session._connect_to("127.0.0.1", 54321)
                    else:
                        await session._connect_to("127.0.0.1", 54321)
        return {
            "uri": seen.get("uri"),
            "max_size": seen.get("max_size"),
            "compression_disabled": seen.get("compression") is None,
            "upgrade_headers": seen.get("additional_headers") or {},
            "preflight_required": preflight.await_count == 1,
            "uses_proxy_socket": "sock" in (seen.get("kwargs") or {}),
        }

    import sys, types
    return asyncio.run(_run())


def _python_ws_runtime_listener_peer_summary() -> dict[str, object]:
    async def _run() -> dict[str, object]:
        session = WebSocketSession(ws_test_fixtures._args("binary"))
        session._loop = asyncio.get_running_loop()
        peer_ws = ws_test_fixtures._FakeWs()
        peer_ws.payload_mode = "base64"
        peer_ws.local_address = ("127.0.0.1", 8080)
        peer_ws.remote_address = ("127.0.0.1", 54321)
        await session._on_accept(peer_ws)
        ctx = session._server_peers[1]
        session._schedule_server_send(ctx, b"\x02pong")
        await asyncio.wait_for(ctx["tx_queue"].join(), timeout=1.0)
        snapshot = {
            "payload_mode": ctx["payload_mode"],
            "decoded_hex": session._decode_ws_message("AnBvbmc=", ctx=ctx).hex(),
            "sent_payload_kind": "text",
            "sent_payload_value": peer_ws.sent[0],
        }
        ctx["rx_task"].cancel()
        await ctx["rx_task"]
        ctx["tx_task"].cancel()
        await ctx["tx_task"]
        return snapshot

    return asyncio.run(_run())


def _python_ws_runtime_proxy_helpers_summary() -> dict[str, object]:
    session = WebSocketSession(ws_test_fixtures._args("binary"))
    return {
        "parsed_proxy": list(WebSocketSession._parse_proxy_spec("http=proxy-http:8080;https=proxy-https:8443", secure=True)),
        "connect_request": session._build_proxy_connect_request("2001:db8::1", 443, auth_header="Negotiate abc123").decode("ascii"),
    }


def _python_tcp_runtime_tx_summary(*, writer_present: bool) -> dict[str, object]:
    args = _overlay_args(overlay_transport="tcp", tcp_peer="127.0.0.1", tcp_peer_port=54321)
    session = TcpStreamSession(args)
    session._loop = asyncio.new_event_loop()
    session._run_flag = True
    peer_tx = []
    session.set_on_peer_tx(peer_tx.append)
    connect_requested = False
    transport = None

    if writer_present:
        transport = _FakeTCPTransport(sockname=("127.0.0.1", 40000), peername=("127.0.0.1", 54321))
        session._writer = _FakeTCPStreamWriter(transport)
    else:
        def _record_connect_once() -> None:
            nonlocal connect_requested
            connect_requested = True

        session._ensure_connect_once = _record_connect_once

    try:
        session.send_app(b"hello")
        return {
            "tx_bytes": session._tx_bytes,
            "peer_tx": peer_tx,
            "written_hex": [frame.hex() for frame in (transport.written if transport is not None else [])],
            "early_buf_bytes": len(session._early_buf),
            "early_buf_hex": session._early_buf.hex() if session._early_buf else None,
            "connect_requested": connect_requested,
        }
    finally:
        session._loop.close()


def _python_tcp_runtime_connect_summary() -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = _overlay_args(overlay_transport="tcp", tcp_peer="127.0.0.1", tcp_peer_port=54321)
        session = TcpStreamSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        wire = session._LEN.pack(6) + b"\x00hello"
        session._buffer_early(wire)
        sock = ws_test_fixtures._FakeSocket()
        transport = _FakeSockoptTCPTransport(
            sockname=("127.0.0.1", 40000),
            peername=("127.0.0.1", 54321),
            sock=sock,
        )
        loop = asyncio.get_running_loop()

        async def _fake_create_connection(factory, host, port):
            return transport, factory()

        async def _fake_rx_pump() -> None:
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                return

        session._rx_pump = _fake_rx_pump

        with mock.patch.object(loop, "create_connection", side_effect=_fake_create_connection):
            await session._connect_to("127.0.0.1", 54321)

        snapshot = {
            "connected": session._writer is not None,
            "peer_host": session._peer_host,
            "peer_port": session._peer_port,
            "keepalive_enabled": (__import__("socket").SOL_SOCKET, __import__("socket").SO_KEEPALIVE, 1) in sock.calls,
            "overlay_connected": session._overlay_connected,
            "bp_task_started": session._bp_task is not None,
            "flushed_hex": [frame.hex() for frame in transport.written],
            "early_buf_bytes": len(session._early_buf),
        }

        session._run_flag = False
        if session._rx_task:
            session._rx_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._rx_task
        if session._bp_task:
            session._bp_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session._bp_task
        if session._writer:
            session._writer.close()
        return snapshot

    return asyncio.run(_run())


def _python_tcp_runtime_socket_config_summary() -> dict[str, object]:
    args = _overlay_args(overlay_transport="tcp", tcp_peer="127.0.0.1", tcp_peer_port=54321)
    session = TcpStreamSession(args)
    sock = ws_test_fixtures._FakeSocket()
    transport = _FakeSockoptTCPTransport(
        sockname=("127.0.0.1", 40000),
        peername=("127.0.0.1", 54321),
        sock=sock,
    )
    writer = _FakeTCPStreamWriter(transport)
    session._enable_os_keepalive(writer)
    return {
        "keepalive_enabled": (__import__("socket").SOL_SOCKET, __import__("socket").SO_KEEPALIVE, 1) in sock.calls,
    }


def _python_tcp_runtime_reconnect_summary() -> dict[str, object]:
    args = _overlay_args(overlay_transport="tcp", tcp_peer="127.0.0.1", tcp_peer_port=54321)
    session = TcpStreamSession(args)
    session._run_flag = True
    session._overlay_connected = True
    loop = asyncio.new_event_loop()
    transport = _FakeTCPTransport(sockname=("127.0.0.1", 40000), peername=("127.0.0.1", 54321))
    session._writer = _FakeTCPStreamWriter(transport)
    session._reader = asyncio.StreamReader(loop=loop)
    reconnect_loop_started = False

    def _record_reconnect_loop() -> None:
        nonlocal reconnect_loop_started
        reconnect_loop_started = True

    session._start_reconnect_loop = _record_reconnect_loop
    try:
        requested = session.request_reconnect()
        return {
            "requested": requested,
            "writer_closed": transport.closed,
            "writer_present": session._writer is not None,
            "reader_present": session._reader is not None,
            "overlay_connected": session._overlay_connected,
            "reconnect_loop_started": reconnect_loop_started,
        }
    finally:
        loop.close()


def _python_tcp_runtime_server_accept_summary() -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = _overlay_args(overlay_transport="tcp", tcp_peer=None)
        session = TcpStreamSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        sock = ws_test_fixtures._FakeSocket()
        transport = _FakeSockoptTCPTransport(
            sockname=("127.0.0.1", 8081),
            peername=("127.0.0.1", 54321),
            sock=sock,
        )
        writer = _FakeTCPStreamWriter(transport)
        reader = asyncio.StreamReader()
        await session._on_accept(reader, writer)
        snapshot = {
            "peer_id": 1,
            "peer_host": session._peer_host,
            "peer_port": session._peer_port,
            "keepalive_enabled": (__import__("socket").SOL_SOCKET, __import__("socket").SO_KEEPALIVE, 1) in sock.calls,
            "overlay_connected": session._overlay_connected,
            "server_peer_ids": sorted(session._server_peers.keys()),
        }
        await session._close_server_peer(1)
        session._run_flag = False
        return snapshot

    return asyncio.run(_run())


def _python_tcp_runtime_server_close_summary() -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = _overlay_args(overlay_transport="tcp", tcp_peer=None)
        session = TcpStreamSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        transport = _FakeTCPTransport(sockname=("127.0.0.1", 8081), peername=("127.0.0.1", 54321))
        writer = _FakeTCPStreamWriter(transport)
        reader = asyncio.StreamReader()
        await session._on_accept(reader, writer)
        await session._close_server_peer(1)
        session._run_flag = False
        return {
            "overlay_connected": session._overlay_connected,
            "server_peer_ids": sorted(session._server_peers.keys()),
        }

    return asyncio.run(_run())


def _python_tcp_runtime_backpressure_summary() -> dict[str, object]:
    async def _run() -> dict[str, object]:
        args = _overlay_args(overlay_transport="tcp", tcp_peer="127.0.0.1", tcp_peer_port=54321)
        session = TcpStreamSession(args)
        session._loop = asyncio.get_running_loop()
        session._run_flag = True
        session._wbuf_threshold = 128
        session._bp_evt = asyncio.Event()
        transport = _FakeSockoptTCPTransport(
            sockname=("127.0.0.1", 40000),
            peername=("127.0.0.1", 54321),
            write_buffer_size=256,
        )
        session._writer = _FakeTCPStreamWriter(transport)
        session._maybe_signal_bp()
        return {
            "bp_signaled": session._bp_evt.is_set(),
        }

    return asyncio.run(_run())


def _python_open_payload(parsed: tuple[object, ...]) -> dict[str, object]:
    return {
        "instance_id": str(parsed[0]),
        "connection_seq": parsed[1],
        "spec": {
            "svc_id": parsed[2],
            "l_proto": mux_proto_name(parsed[3]),
            "l_bind": parsed[4],
            "l_port": parsed[5],
            "r_proto": mux_proto_name(parsed[6]),
            "r_host": parsed[7],
            "r_port": parsed[8],
            "name": parsed[9],
            "lifecycle_hooks": parsed[10],
            "options": parsed[11],
        },
    }


def mux_proto_name(value: object) -> str:
    if value == ChannelMux.Proto.UDP or value == int(ChannelMux.Proto.UDP):
        return "udp"
    if value == ChannelMux.Proto.TCP or value == int(ChannelMux.Proto.TCP):
        return "tcp"
    if value == ChannelMux.Proto.TUN or value == int(ChannelMux.Proto.TUN):
        return "tun"
    raise AssertionError(f"unsupported proto value: {value!r}")


def _service_spec_payload(spec: ChannelMux.ServiceSpec) -> dict[str, object]:
    return {
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
    }


class _SecureLinkInnerSession:
    def set_on_app_payload(self, cb):
        self._on_app = cb

    def set_on_state_change(self, cb):
        self._on_state = cb

    def set_on_peer_rx(self, cb):
        self._on_peer_rx = cb

    def set_on_peer_tx(self, cb):
        self._on_peer_tx = cb

    def set_on_peer_set(self, cb):
        self._on_peer_set = cb

    def set_on_peer_disconnect(self, cb):
        self._on_peer_disconnect = cb

    def set_on_app_from_peer_bytes(self, cb):
        self._on_app_from_peer_bytes = cb

    def set_on_transport_epoch_change(self, cb):
        self._on_transport_epoch_change = cb

    def get_max_app_payload_size(self):
        return 65535


def _make_securelink_session(psk: str = "lab-secret") -> object:
    args = argparse.Namespace(
        secure_link=True,
        secure_link_mode="psk",
        secure_link_psk=psk,
        secure_link_require=False,
        secure_link_rekey_after_frames=0,
        secure_link_rekey_after_seconds=0.0,
        secure_link_retry_backoff_initial_ms=1000,
        secure_link_retry_backoff_max_ms=5000,
        secure_link_recover_after_failure=True,
        secure_link_recover_delay_seconds=30.0,
        tcp_peer=None,
    )
    from obstacle_bridge.bridge import SecureLinkPskSession

    return SecureLinkPskSession(_SecureLinkInnerSession(), args, "tcp")


def _make_udp_protocol() -> Protocol:
    return Protocol(BaseFrameV2)


class _FakeDatagramTransport:
    def __init__(self) -> None:
        self.frames: list[bytes] = []

    def sendto(self, data: bytes, addr=None):
        self.frames.append(bytes(data))


class _FakeConnectedDatagramTransport(_FakeDatagramTransport):
    def __init__(self, *, sockname: tuple[str, int], peername: tuple[str, int]) -> None:
        super().__init__()
        self.sockname = (sockname[0], int(sockname[1]))
        self.peername = (peername[0], int(peername[1]))
        self.closed = False

    def get_extra_info(self, name):
        if name == "sockname":
            return self.sockname
        if name == "peername":
            return self.peername
        return None

    def close(self) -> None:
        self.closed = True


class _FakeTCPTransport:
    def __init__(self, *, sockname: tuple[str, int], peername: tuple[str, int]) -> None:
        self.sockname = (sockname[0], int(sockname[1]))
        self.peername = (peername[0], int(peername[1]))
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def can_write_eof(self) -> bool:
        return False

    def get_write_buffer_size(self) -> int:
        return 0

    def get_extra_info(self, name: str):
        if name == "sockname":
            return self.sockname
        if name == "peername":
            return self.peername
        return None


class _FakeSockoptTCPTransport(_FakeTCPTransport):
    def __init__(self, *, sockname: tuple[str, int], peername: tuple[str, int], sock=None, write_buffer_size: int = 0) -> None:
        super().__init__(sockname=sockname, peername=peername)
        self.sock = sock
        self.write_buffer_size = int(write_buffer_size)

    def get_write_buffer_size(self) -> int:
        return self.write_buffer_size

    def get_extra_info(self, name: str):
        if name == "socket":
            return self.sock
        return super().get_extra_info(name)


class _FakeStreamReaderProtocol(asyncio.StreamReaderProtocol):
    def __init__(self, reader: asyncio.StreamReader) -> None:
        super().__init__(reader)
        self._close_waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    def _get_close_waiter(self, stream_writer):
        return self._close_waiter


class _FakeTCPStreamWriter:
    def __init__(self, transport: _FakeTCPTransport) -> None:
        self.transport = transport

    def write(self, data: bytes) -> None:
        self.transport.write(data)

    def get_extra_info(self, name: str):
        return self.transport.get_extra_info(name)

    def close(self) -> None:
        self.transport.close()

    async def wait_closed(self) -> None:
        return None

    async def drain(self) -> None:
        return None


class _FakeAsyncReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = [bytes(chunk) for chunk in chunks]

    async def read(self, count: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class _ControllableAsyncReader:
    def __init__(self, loop: asyncio.AbstractEventLoop, chunks: list[bytes]) -> None:
        self._loop = loop
        self._chunks = [bytes(chunk) for chunk in chunks]
        self._eof = False
        self._waiter: asyncio.Future[None] | None = None

    async def read(self, count: int) -> bytes:
        while True:
            if self._chunks:
                return self._chunks.pop(0)
            if self._eof:
                return b""
            if self._waiter is None or self._waiter.done():
                self._waiter = self._loop.create_future()
            await self._waiter

    def feed_eof(self) -> None:
        self._eof = True
        if self._waiter is not None and not self._waiter.done():
            self._waiter.set_result(None)

    def feed_data(self, data: bytes) -> None:
        self._chunks.append(bytes(data))
        if self._waiter is not None and not self._waiter.done():
            self._waiter.set_result(None)


class _FakeServerSocket:
    def __init__(self, sockname: tuple[str, int]) -> None:
        self._sockname = (sockname[0], int(sockname[1]))

    def getsockname(self) -> tuple[str, int]:
        return self._sockname


class _FakeAsyncioServer:
    def __init__(self, sockname: tuple[str, int]) -> None:
        self.sockets = [_FakeServerSocket(sockname)]


def _start_fake_tcp_server(
    mux: ChannelMux,
    spec: ChannelMux.ServiceSpec,
    svc_key: tuple[str, int, int],
):
    captured: dict[str, object] = {}

    async def _fake_start_server(handler, host, port, family=None):
        captured["handler"] = handler
        return _FakeAsyncioServer((str(host), int(port)))

    with mock.patch("asyncio.start_server", side_effect=_fake_start_server):
        mux.loop.run_until_complete(mux._start_tcp_server_for(spec, svc_key))
    handler = captured.get("handler")
    assert handler is not None
    return handler


def _udp_open_key_string(key: tuple[object, ...] | None) -> str | None:
    if key is None:
        return None
    return ":".join(str(part) for part in key)


def _python_udp_client_open_snapshot(
    mux: ChannelMux,
    chan: int,
    *,
    connect_requested: bool,
    connected: bool,
    replaced_channel_id: int | None = None,
    duplicate_active_channel_id: int | None = None,
) -> dict[str, object]:
    return {
        "accepted": duplicate_active_channel_id is None,
        "service_id": mux._udp_client_svc_id.get(chan),
        "open_key": _udp_open_key_string(mux._udp_open_key_by_chan.get(chan)),
        "replaced_channel_id": replaced_channel_id,
        "duplicate_active_channel_id": duplicate_active_channel_id,
        "connect_requested": connect_requested,
        "connected": connected,
        "pending_count": len(mux._udp_client_pending.get(chan, [])),
        "open_channels": sorted(mux._udp_open_key_by_chan.keys()),
        "connected_channels": sorted(mux._udp_client_transports.keys()),
    }


def _python_udp_client_connect_snapshot(
    mux: ChannelMux,
    chan: int,
    transport: _FakeConnectedDatagramTransport,
    *,
    flushed_packets: list[bytes],
) -> dict[str, object]:
    return {
        "connected": chan in mux._udp_client_transports,
        "service_id": mux._udp_client_svc_id.get(chan),
        "open_key": _udp_open_key_string(mux._udp_open_key_by_chan.get(chan)),
        "pending_count": len(mux._udp_client_pending.get(chan, [])),
        "flushed_packets_hex": [packet.hex() for packet in flushed_packets],
        "local_addr_host": transport.sockname[0],
        "local_addr_port": transport.sockname[1],
        "peer_addr_host": transport.peername[0],
        "peer_addr_port": transport.peername[1],
        "connected_channels": sorted(mux._udp_client_transports.keys()),
    }


def _python_udp_client_data_snapshot(
    *,
    mux: ChannelMux,
    chan: int,
    transport: _FakeConnectedDatagramTransport,
    buffered: bool,
    dropped: bool,
    sent_immediately: bool,
    sent_packets: list[bytes],
) -> dict[str, object]:
    return {
        "buffered": buffered,
        "dropped": dropped,
        "sent_immediately": sent_immediately,
        "pending_count": len(mux._udp_client_pending.get(chan, [])),
        "sent_packets_hex": [packet.hex() for packet in sent_packets],
    }


def _python_udp_client_fragment_snapshot(
    *,
    mux: ChannelMux,
    chan: int,
    transport: _FakeConnectedDatagramTransport,
    before_frame_count: int,
    datagram_id: int,
    total_len: int,
    received_bytes: int,
) -> dict[str, object]:
    sent_packets = transport.frames[before_frame_count:]
    return {
        "buffered": False,
        "dropped": False,
        "sent_immediately": bool(sent_packets),
        "pending_count": len(mux._udp_client_pending.get(chan, [])),
        "sent_packets_hex": [packet.hex() for packet in sent_packets],
        "datagram_id": datagram_id,
        "total_len": total_len,
        "received_bytes": received_bytes,
    }


def _python_udp_client_close_snapshot(mux: ChannelMux, chan: int) -> dict[str, object]:
    return {
        "closed": True,
        "chan_id": chan,
        "open_channels": sorted(mux._udp_open_key_by_chan.keys()),
        "connected_channels": sorted(mux._udp_client_transports.keys()),
        "pending_channels": sorted(mux._udp_client_pending.keys()),
    }


def _tcp_open_key_string(key: tuple[object, ...] | None) -> str | None:
    if key is None:
        return None
    return ":".join(str(part) for part in key)


def _python_tcp_client_open_snapshot(
    mux: ChannelMux,
    chan: int,
    *,
    connect_requested: bool,
    connected: bool,
) -> dict[str, object]:
    return {
        "accepted": True,
        "service_id": mux._tcp_open_key_by_chan.get(chan, (None, None))[1],
        "open_key": _tcp_open_key_string(mux._tcp_open_key_by_chan.get(chan)),
        "connect_requested": connect_requested,
        "connected": connected,
        "pending_count": len(mux._tcp_pending_data.get(chan, [])),
        "open_channels": sorted(mux._tcp_open_key_by_chan.keys()),
        "connected_channels": sorted(mux._tcp_by_chan.keys()),
    }


def _python_tcp_client_connect_snapshot(
    mux: ChannelMux,
    chan: int,
    transport: _FakeTCPTransport,
    *,
    flushed_buffers: list[bytes],
) -> dict[str, object]:
    return {
        "connected": chan in mux._tcp_by_chan,
        "service_id": mux._tcp_by_chan.get(chan, (None,))[0],
        "open_key": _tcp_open_key_string(mux._tcp_open_key_by_chan.get(chan)),
        "pending_count": len(mux._tcp_pending_data.get(chan, [])),
        "flushed_buffers_hex": [packet.hex() for packet in flushed_buffers],
        "local_addr_host": transport.sockname[0],
        "local_addr_port": transport.sockname[1],
        "peer_addr_host": transport.peername[0],
        "peer_addr_port": transport.peername[1],
        "connected_channels": sorted(mux._tcp_by_chan.keys()),
    }


def _python_tcp_client_data_snapshot(
    *,
    mux: ChannelMux,
    chan: int,
    buffered: bool,
    sent_immediately: bool,
    written_buffers: list[bytes],
) -> dict[str, object]:
    return {
        "buffered": buffered,
        "sent_immediately": sent_immediately,
        "pending_count": len(mux._tcp_pending_data.get(chan, [])),
        "written_buffers_hex": [packet.hex() for packet in written_buffers],
    }


def _python_tcp_client_close_snapshot(mux: ChannelMux, chan: int) -> dict[str, object]:
    return {
        "closed": True,
        "chan_id": chan,
        "open_channels": sorted(mux._tcp_open_key_by_chan.keys()),
        "connected_channels": sorted(mux._tcp_by_chan.keys()),
        "pending_channels": sorted(mux._tcp_pending_data.keys()),
    }


def _python_tcp_client_local_close_snapshot(
    mux: ChannelMux,
    chan: int,
    frames: list[bytes],
) -> dict[str, object]:
    return {
        "closed": True,
        "chan_id": chan,
        "frames_hex": [frame.hex() for frame in frames],
        "open_channels": sorted(mux._tcp_open_key_by_chan.keys()),
        "connected_channels": sorted(mux._tcp_by_chan.keys()),
        "pending_channels": sorted(mux._tcp_pending_data.keys()),
    }


def _python_tcp_server_accept_snapshot(mux: ChannelMux, chan: int) -> dict[str, object]:
    return {
        "chan_id": chan,
        "frames_hex": [frame.hex() for frame in mux.session.sent],
        "next_tcp_id": mux._next_tcp_id,
        "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.TCP)],
        "active_channels": sorted(mux._tcp_by_chan.keys()),
    }


def _python_tcp_server_data_snapshot(mux: ChannelMux, chan: int, frames: list[bytes]) -> dict[str, object]:
    return {
        "sent": bool(frames),
        "frames_hex": [frame.hex() for frame in frames],
        "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.TCP)],
        "active_channels": sorted(mux._tcp_by_chan.keys()),
    }


def _python_tcp_server_inbound_snapshot(writer: _FakeTCPStreamWriter) -> dict[str, object]:
    return {
        "delivered": bool(writer.transport.written),
        "written_buffers_hex": [frame.hex() for frame in writer.transport.written],
    }


def _python_tcp_server_close_snapshot(mux: ChannelMux, chan: int, frames: list[bytes]) -> dict[str, object]:
    return {
        "closed": True,
        "chan_id": chan,
        "frames_hex": [frame.hex() for frame in frames],
        "active_channels": sorted(mux._tcp_by_chan.keys()),
    }


def _send_meta_payload(session: Session) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for counter in sorted(session.send_meta):
        frame_type, len_or_offset, chunk = session.send_meta[counter]
        payload.append(
            {
                "counter": counter,
                "frame_type": frame_type,
                "len_or_offset": len_or_offset,
                "data_hex": bytes(chunk).hex(),
            }
        )
    return payload


def _int_keyed_map(values: dict[int, int]) -> dict[str, int]:
    return {str(key): value for key, value in sorted(values.items())}


def _python_inbound_control_summary(
    *,
    send_port_present: bool,
    packet_last_in_order: int,
    packet_highest: int,
    packet_missed: list[int],
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)
    session.proto.rtt_est_ms = 100.0
    pre_send_buffer = sorted(session.send_buf)
    pre_send_meta = _send_meta_payload(session)
    pre_send_tx_ns = _int_keyed_map(session.send_txns)
    pre_send_attempts = _int_keyed_map(dict(session.send_attempts))
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    control_reasons: list[str] = []
    proto._emit_control = lambda _now_t, reason="timer_paced": control_reasons.append(reason)  # type: ignore[method-assign]
    before_frames = len(transport.frames)
    now_ns = max(session.send_txns.values()) + 150_000_000
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        session.confirm_with_feedback(packet_last_in_order, packet_highest, packet_missed)
        proto._schedule_retrans(packet_missed)
        flush_count = session.try_flush_send_queue(transport) if proto.send_port else 0
        proto._evaluate_control_policy_inbound(False)
    return {
        "send_buffer": sorted(session.send_buf),
        "peer_reported_missing": sorted(session.peer_reported_missing),
        "last_ack_peer": session.last_ack_peer,
        "emitted_counters": [
            DataPacket.parse_full(frame).pkt_counter
            for frame in transport.frames[before_frames:]
            if DataPacket.parse_full(frame) is not None
        ],
        "frames_hex": [frame.hex() for frame in transport.frames[before_frames:]],
        "last_retx_ns": _int_keyed_map(session.last_retx_ns),
        "send_attempts": _int_keyed_map(dict(session.send_attempts)),
        "peer_missed_count": session.peer_missed_count,
        "last_send_ns": str(session.last_send_ns),
        "flush_requested": bool(proto.send_port),
        "flush_count": flush_count,
        "control_should_emit": bool(control_reasons),
        "control_reason": control_reasons[0] if control_reasons else None,
        "now_ns": now_ns,
        "pre_send_buffer": pre_send_buffer,
        "pre_send_meta": pre_send_meta,
        "pre_send_tx_ns": pre_send_tx_ns,
        "pre_send_attempts": pre_send_attempts,
    }


def _python_inbound_idle_summary(
    *,
    send_port_present: bool,
    tx_ns: int,
    echo_ns: int,
    now_ns: int,
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None

    session.proto.on_frame_received(tx_ns, now_ns)
    if echo_ns:
        with mock.patch.object(myudp, "now_ns", return_value=now_ns):
            session.update_rtt(echo_ns, from_idle=True)
            if proto._established_ns == 0:
                proto._established_ns = now_ns

    reflected_frame = None
    if echo_ns == 0 and proto.send_port is not None:
        with mock.patch.object(myudp, "now_ns", return_value=now_ns):
            frame = session.proto.build_frame(session.proto.PTYPE_IDLE, b"", initial=False)
        transport.sendto(frame)
        reflected_frame = frame.hex()

    return {
        "reflected": reflected_frame is not None,
        "reflected_frame_hex": reflected_frame,
        "established_ns": str(proto._established_ns),
        "last_rx_tx_ns": str(session.proto._last_rx_tx_ns),
        "last_rx_wall_ns": str(session.proto._last_rx_wall_ns),
        "rtt_sample_ms": session.rtt_sample_ms,
        "rtt_est_ms": session.rtt_est_ms,
        "transmit_delay_est_ms": session.transmit_delay_est_ms,
    }


def _python_inbound_data_summary(
    *,
    pre_frames: list[bytes],
    frame: bytes,
    tx_ns: int,
    echo_ns: int,
    now_ns: int,
    send_port_present: bool,
    last_sent_last_in_order: int,
    last_control_sent_ns: int,
    established_ns: int,
    prior_rtt_est_ms: float,
    prior_transmit_delay_est_ms: float,
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    proto._last_sent_last_in_order = last_sent_last_in_order
    proto._last_control_sent_ns = last_control_sent_ns
    proto._established_ns = established_ns
    session.proto.rtt_est_ms = prior_rtt_est_ms
    session.transmit_delay_est_ms = prior_transmit_delay_est_ms
    control_reasons: list[str] = []
    proto._emit_control = lambda _now_t, reason="timer_paced": control_reasons.append(reason) if proto.send_port is not None else None  # type: ignore[method-assign]

    for raw in pre_frames:
        packet = DataPacket.parse_full(raw)
        assert packet is not None
        session.process_data(packet)

    packet = DataPacket.parse_full(frame)
    assert packet is not None
    session.proto.on_frame_received(tx_ns, now_ns)
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        if echo_ns:
            session.update_rtt(echo_ns, from_idle=False)
            if proto._established_ns == 0:
                proto._established_ns = now_ns
        prev_missing = set(session.missing)
        _advanced, completed = session.process_data(packet)
        if packet.pkt_counter in prev_missing and packet.pkt_counter not in session.missing:
            proto._emit_control(now_ns, reason="gap_filled_ack")
        grew_missing = len(session.missing - prev_missing) > 0
        proto._evaluate_control_policy_inbound(grew_missing)

    return {
        "control_reasons": control_reasons,
        "completed_hex": [payload.hex() for payload in completed],
        "expected": session.expected,
        "pending": sorted(session.pending),
        "missing": sorted(session.missing),
        "established_ns": str(proto._established_ns),
        "last_rx_tx_ns": str(session.proto._last_rx_tx_ns),
        "last_rx_wall_ns": str(session.proto._last_rx_wall_ns),
        "rtt_sample_ms": session.rtt_sample_ms,
        "rtt_est_ms": session.rtt_est_ms,
        "transmit_delay_est_ms": session.transmit_delay_est_ms,
    }


def _python_peer_runtime_data_sequence_summary(
    *,
    events: list[dict[str, int | str]],
    send_port_present: bool,
    last_sent_last_in_order: int,
    last_control_sent_ns: int,
    established_ns: int,
    prior_rtt_est_ms: float,
    prior_transmit_delay_est_ms: float,
) -> list[dict[str, object]]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    proto._last_sent_last_in_order = last_sent_last_in_order
    proto._last_control_sent_ns = last_control_sent_ns
    proto._established_ns = established_ns
    session.proto.rtt_est_ms = prior_rtt_est_ms
    session.transmit_delay_est_ms = prior_transmit_delay_est_ms

    snapshots: list[dict[str, object]] = []
    for event in events:
        frame = bytes.fromhex(str(event["frame_hex"]))
        packet = DataPacket.parse_full(frame)
        assert packet is not None
        tx_ns = int(event["tx_ns"])
        echo_ns = int(event["echo_ns"])
        now_ns = int(event["now_ns"])

        control_reasons: list[str] = []
        proto._emit_control = lambda _now_t, reason="timer_paced": control_reasons.append(reason) if proto.send_port is not None else None  # type: ignore[method-assign]
        session.proto.on_frame_received(tx_ns, now_ns)
        with mock.patch.object(myudp, "now_ns", return_value=now_ns):
            if echo_ns:
                session.update_rtt(echo_ns, from_idle=False)
                if proto._established_ns == 0:
                    proto._established_ns = now_ns
            prev_missing = set(session.missing)
            _advanced, completed = session.process_data(packet)
            if packet.pkt_counter in prev_missing and packet.pkt_counter not in session.missing:
                proto._emit_control(now_ns, reason="gap_filled_ack")
            grew_missing = len(session.missing - prev_missing) > 0
            proto._evaluate_control_policy_inbound(grew_missing)

        snapshots.append(
            {
                "control_reasons": control_reasons,
                "completed_hex": [payload.hex() for payload in completed],
                "expected": session.expected,
                "pending": sorted(session.pending),
                "missing": sorted(session.missing),
                "established_ns": str(proto._established_ns),
                "last_rx_tx_ns": str(session.proto._last_rx_tx_ns),
                "last_rx_wall_ns": str(session.proto._last_rx_wall_ns),
                "rtt_sample_ms": session.rtt_sample_ms,
                "rtt_est_ms": session.rtt_est_ms,
                "transmit_delay_est_ms": session.transmit_delay_est_ms,
                "last_sent_last_in_order": proto._last_sent_last_in_order,
                "last_control_sent_ns": str(proto._last_control_sent_ns),
            }
        )

    return snapshots


def _python_peer_runtime_idle_sequence_summary(
    *,
    events: list[dict[str, int]],
    send_port_present: bool,
    established_ns: int,
    prior_rtt_est_ms: float,
    prior_transmit_delay_est_ms: float,
) -> list[dict[str, object]]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    proto._established_ns = established_ns
    session.proto.rtt_est_ms = prior_rtt_est_ms
    session.transmit_delay_est_ms = prior_transmit_delay_est_ms

    snapshots: list[dict[str, object]] = []
    for event in events:
        tx_ns = int(event["tx_ns"])
        echo_ns = int(event["echo_ns"])
        now_ns = int(event["now_ns"])
        session.proto.on_frame_received(tx_ns, now_ns)

        reflected_frame = None
        with mock.patch.object(myudp, "now_ns", return_value=now_ns):
            if echo_ns:
                session.update_rtt(echo_ns, from_idle=True)
                if proto._established_ns == 0:
                    proto._established_ns = now_ns
            elif proto.send_port is not None:
                frame = session.proto.build_frame(session.proto.PTYPE_IDLE, b"", initial=False)
                transport.sendto(frame)
                reflected_frame = frame.hex()

        snapshots.append(
            {
                "reflected": reflected_frame is not None,
                "reflected_frame_hex": reflected_frame,
                "established_ns": str(proto._established_ns),
                "last_rx_tx_ns": str(session.proto._last_rx_tx_ns),
                "last_rx_wall_ns": str(session.proto._last_rx_wall_ns),
                "rtt_sample_ms": session.rtt_sample_ms,
                "rtt_est_ms": session.rtt_est_ms,
                "transmit_delay_est_ms": session.transmit_delay_est_ms,
            }
        )

    return snapshots


def _python_peer_runtime_control_sequence_summary(
    *,
    events: list[dict[str, object]],
    send_port_present: bool,
    established_ns: int,
    last_sent_last_in_order: int,
    last_control_sent_ns: int,
    prior_rtt_est_ms: float,
    prior_transmit_delay_est_ms: float,
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    proto._established_ns = established_ns
    proto._last_sent_last_in_order = last_sent_last_in_order
    proto._last_control_sent_ns = last_control_sent_ns
    session.proto.rtt_est_ms = prior_rtt_est_ms
    session.transmit_delay_est_ms = prior_transmit_delay_est_ms

    snapshots: list[dict[str, object]] = []
    before_frames = len(transport.frames)
    def _int_keyed_str_map(values: dict[int, int]) -> dict[str, str]:
        return {str(key): str(value) for key, value in sorted(values.items())}

    for event in events:
        control_reasons: list[str] = []
        proto._emit_control = lambda _now_t, reason="timer_paced": control_reasons.append(reason)  # type: ignore[method-assign]
        now_ns = int(event["now_ns"])
        with mock.patch.object(myudp, "now_ns", return_value=now_ns):
            session.confirm_with_feedback(
                int(event["packet_last_in_order"]),
                int(event["packet_highest"]),
                list(event["packet_missed"]),
            )
            proto._schedule_retrans(list(event["packet_missed"]))
            flush_count = session.try_flush_send_queue(transport) if proto.send_port else 0
            proto._evaluate_control_policy_inbound(False)
        emitted_frames = transport.frames[before_frames:]
        snapshots.append(
            {
                "send_buffer": sorted(session.send_buf),
                "peer_reported_missing": sorted(session.peer_reported_missing),
                "last_ack_peer": session.last_ack_peer,
                "emitted_counters": [
                    DataPacket.parse_full(frame).pkt_counter
                    for frame in emitted_frames
                    if DataPacket.parse_full(frame) is not None
                ],
                "frames_hex": [frame.hex() for frame in emitted_frames],
                "last_retx_ns": _int_keyed_str_map(session.last_retx_ns),
                "send_attempts": _int_keyed_map(dict(session.send_attempts)),
                "peer_missed_count": session.peer_missed_count,
                "last_send_ns": str(session.last_send_ns),
                "flush_requested": bool(proto.send_port),
                "flush_count": flush_count,
                "control_should_emit": bool(control_reasons),
                "control_reason": control_reasons[0] if control_reasons else None,
                "last_sent_last_in_order": proto._last_sent_last_in_order,
                "last_control_sent_ns": str(proto._last_control_sent_ns),
            }
        )
        before_frames = len(transport.frames)
    return {"snapshots": snapshots}


def _python_peer_runtime_control_timer_summary(
    *,
    pre_frames: list[bytes],
    send_port_present: bool,
    now_ns: int,
    established_ns: int,
    last_sent_last_in_order: int,
    last_control_sent_ns: int,
    prior_rtt_est_ms: float,
    prior_transmit_delay_est_ms: float,
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    proto._established_ns = established_ns
    proto._last_sent_last_in_order = last_sent_last_in_order
    proto._last_control_sent_ns = last_control_sent_ns
    session.proto.rtt_est_ms = prior_rtt_est_ms
    session.transmit_delay_est_ms = prior_transmit_delay_est_ms

    for raw in pre_frames:
        packet = DataPacket.parse_full(raw)
        assert packet is not None
        session.process_data(packet)

    control_reasons: list[str] = []
    def _capture_emit_control(now_t: int, reason: str = "timer_paced") -> None:
        if proto.send_port is None:
            return
        control_reasons.append(reason)
        proto._last_control_sent_ns = now_t
        proto._last_sent_last_in_order = session.last_in_order()

    proto._emit_control = _capture_emit_control  # type: ignore[method-assign]
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        proto._evaluate_control_policy_timer()

    return {
        "control_should_emit": bool(control_reasons),
        "control_reason": control_reasons[0] if control_reasons else None,
        "last_sent_last_in_order": proto._last_sent_last_in_order,
        "last_control_sent_ns": str(proto._last_control_sent_ns),
    }


def _python_peer_runtime_retransmit_timer_summary(
    *,
    now_ns: int,
    send_port_present: bool,
    prior_rtt_est_ms: float,
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport if send_port_present else None
    session.proto.rtt_est_ms = prior_rtt_est_ms
    session.peer_reported_missing = {1}
    before_frames = len(transport.frames)

    def _int_keyed_str_map(values: dict[int, int]) -> dict[str, str]:
        return {str(key): str(value) for key, value in sorted(values.items())}

    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        proto._retx_sweep_reported_missing()
        proto._retx_sweep_unconfirmed()

    emitted_frames = transport.frames[before_frames:]
    return {
        "emitted_counters": [
            DataPacket.parse_full(frame).pkt_counter
            for frame in emitted_frames
            if DataPacket.parse_full(frame) is not None
        ],
        "frames_hex": [frame.hex() for frame in emitted_frames],
        "last_retx_ns": _int_keyed_str_map(session.last_retx_ns),
        "send_attempts": _int_keyed_map(dict(session.send_attempts)),
        "peer_reported_missing": sorted(session.peer_reported_missing),
        "peer_missed_count": session.peer_missed_count,
        "last_send_ns": str(session.last_send_ns),
        "send_buffer": sorted(session.send_buf),
        "send_meta": _send_meta_payload(session),
        "send_tx_ns": _int_keyed_map(session.send_txns),
        "last_retx_ns_seed": {},
        "last_ack_peer": session.last_ack_peer,
    }


def _python_peer_runtime_send_payload_summary(
    *,
    payload: bytes,
    now_ns: int,
    echo_ns: int,
    next_counter: int,
) -> dict[str, object]:
    transport = _FakeDatagramTransport()
    session = Session(proto=Protocol(BaseFrameV2))
    session.next_ctr = next_counter
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        session.send_application_payload(payload, transport)
    return {
        "counters": [
            DataPacket.parse_full(frame).pkt_counter
            for frame in transport.frames
            if DataPacket.parse_full(frame) is not None
        ],
        "frames_hex": [frame.hex() for frame in transport.frames],
        "send_buffer": sorted(session.send_buf),
        "send_tx_ns": {str(key): str(value) for key, value in sorted(session.send_txns.items())},
        "send_attempts": _int_keyed_map(dict(session.send_attempts)),
        "last_send_ns": str(session.last_send_ns),
        "next_counter": session.next_ctr,
    }


def _python_peer_runtime_build_control_summary(
    *,
    pre_frames: list[bytes],
    now_ns: int,
    echo_ns: int,
) -> dict[str, object]:
    session = Session(proto=Protocol(BaseFrameV2))
    for raw in pre_frames:
        packet = DataPacket.parse_full(raw)
        assert packet is not None
        session.process_data(packet)
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        control = session.build_control()
    return {
        "frame_hex": control.raw.hex(),
        "last_sent_last_in_order": session.last_in_order(),
        "last_control_sent_ns": str(now_ns),
    }


def _python_channelmux_local_tun_packet_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1500, "tun", "obtun1", 1500)
        svc_key = ("local", 0, 3)
        mux._local_services[svc_key] = spec
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1500, service_key=svc_key)
        mux._on_local_tun_packet(dev, b"abc")
        return {
            "chan_id": dev.chan_id,
            "allocated_channel": True,
            "frames_hex": [frame.hex() for frame in mux.session.sent],
            "next_tun_id": mux._next_tun_id,
            "next_counter": mux._mux_counters[(dev.chan_id, ChannelMux.Proto.TUN)],
            "spec": _service_spec_payload(spec),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_inbound_tun_data_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    delivered: list[bytes] = []
    try:
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1500, service_key=None, chan_id=7)
        mux._tun_by_chan[7] = dev
        mux._write_tun_packet = lambda _dev, data: delivered.append(bytes(data))  # type: ignore[method-assign]
        mux._rx_tun_data(7, b"abc")
        return {
            "delivered": bool(delivered),
            "packet_hex": delivered[0].hex() if delivered else None,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tun_open_then_local_packet_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        local_spec = ChannelMux.ServiceSpec(3, "tun", "ios-utun", 1600, "tun", "peer-utun", 1600)
        peer_spec = ChannelMux.ServiceSpec(9, "tun", "peer-utun", 1600, "tun", "ios-utun", 1600)
        payload = mux._build_open_v4(peer_spec)
        mux._rx_tun_open(7, payload)
        dev = ChannelMux.TunDevice(fd=-1, ifname="ios-utun", mtu=1600, service_key=("local", 0, 3), chan_id=7)
        mux._tun_by_chan[7] = dev
        mux._on_local_tun_packet(dev, b"abc")
        return {
            "open_snapshot": {
                "accepted": True,
                "chan_id": 7,
                "preferred_chan_id": 7,
                "remote_spec": _service_spec_payload(peer_spec),
            },
            "local_snapshot": {
                "chan_id": 7,
                "allocated_channel": False,
                "frames_hex": [frame.hex() for frame in mux.session.sent],
                "next_tun_id": mux._next_tun_id,
                "next_counter": mux._mux_counters[(7, ChannelMux.Proto.TUN)],
            },
            "local_spec": _service_spec_payload(local_spec),
            "open_payload_hex": payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_local_tun_chunked_open_summary() -> dict[str, object]:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(
            3,
            "tun",
            "ios-utun",
            1600,
            "tun",
            "peer-utun",
            1600,
            options={"pad": "x" * 220},
        )
        svc_key = ("local", 0, 3)
        mux._local_services[svc_key] = spec
        dev = ChannelMux.TunDevice(fd=-1, ifname="ios-utun", mtu=1600, service_key=svc_key)
        mux._on_local_tun_packet(dev, b"abc")
        return {
            "chan_id": dev.chan_id,
            "allocated_channel": True,
            "frames_hex": [frame.hex() for frame in mux.session.sent],
            "next_tun_id": mux._next_tun_id,
            "next_counter": mux._mux_counters[(dev.chan_id, ChannelMux.Proto.TUN)],
            "spec": _service_spec_payload(spec),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_local_tun_throttle_sequence_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(3, "tun", "obtun0", 1500, "tun", "obtun1", 1500)
        svc_key = ("local", 0, 3)
        mux._local_services[svc_key] = spec
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=1500, service_key=svc_key)
        snapshots: list[object] = []
        mux.session._metrics.waiting_count = 0
        with mock.patch("obstacle_bridge.bridge_channelmux.time.monotonic_ns", side_effect=[0, 100_000_000, 100_000_000]):
            mux._on_local_tun_packet(dev, b"a" * 100)
            snapshots.append(
                {
                    "chan_id": dev.chan_id,
                    "allocated_channel": True,
                    "frames_hex": [frame.hex() for frame in mux.session.sent],
                    "next_tun_id": mux._next_tun_id,
                    "next_counter": mux._mux_counters[(dev.chan_id, ChannelMux.Proto.TUN)],
                }
            )
            mux.session._metrics.waiting_count = 1
            before_second = len(mux.session.sent)
            mux._on_local_tun_packet(dev, b"b" * 80)
            snapshots.append(
                {
                    "chan_id": dev.chan_id,
                    "allocated_channel": False,
                    "frames_hex": [frame.hex() for frame in mux.session.sent[before_second:]],
                    "next_tun_id": mux._next_tun_id,
                    "next_counter": mux._mux_counters[(dev.chan_id, ChannelMux.Proto.TUN)],
                }
            )
            before_third = len(mux.session.sent)
            mux._on_local_tun_packet(dev, b"c" * 20)
            snapshots.append(
                None if len(mux.session.sent) == before_third else {
                    "chan_id": dev.chan_id,
                    "allocated_channel": False,
                    "frames_hex": [frame.hex() for frame in mux.session.sent[before_third:]],
                    "next_tun_id": mux._next_tun_id,
                    "next_counter": mux._mux_counters[(dev.chan_id, ChannelMux.Proto.TUN)],
                }
            )
        return {
            "snapshots": snapshots,
            "spec": _service_spec_payload(spec),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_inbound_tun_fragment_sequence_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    delivered: list[bytes] = []
    snapshots: list[dict[str, object]] = []
    payload = bytes(index % 251 for index in range(180))
    datagram_id = 4
    chunks = [payload[0:70], payload[70:140], payload[140:180]]
    fragments = [
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 0) + chunks[0],
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 70) + chunks[1],
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 140) + chunks[2],
    ]
    try:
        dev = ChannelMux.TunDevice(fd=-1, ifname="obtun0", mtu=200, service_key=None, chan_id=7)
        mux._tun_by_chan[7] = dev
        mux._write_tun_packet = lambda _dev, data: delivered.append(bytes(data))  # type: ignore[method-assign]
        for fragment in fragments:
            before = len(delivered)
            mux._rx_tun_fragment(7, fragment)
            snapshots.append(
                {
                    "delivered": len(delivered) > before,
                    "packet_hex": delivered[-1].hex() if len(delivered) > before else None,
                    "datagram_id": datagram_id,
                    "total_len": len(payload),
                    "received_bytes": sum(len(part) for part in fragments[: len(snapshots) + 1]) - 8 * (len(snapshots) + 1),
                }
            )
        return {
            "fragments_hex": [fragment.hex() for fragment in fragments],
            "snapshots": snapshots,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tun_close_then_local_packet_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        local_spec = ChannelMux.ServiceSpec(3, "tun", "ios-utun", 1600, "tun", "peer-utun", 1600)
        peer_spec = ChannelMux.ServiceSpec(9, "tun", "peer-utun", 1600, "tun", "ios-utun", 1600)
        svc_key = ("local", 0, 3)
        mux._local_services[svc_key] = local_spec
        payload = mux._build_open_v4(peer_spec)
        mux._rx_tun_open(7, payload)
        mux._rx_tun_close(7)
        dev = ChannelMux.TunDevice(fd=-1, ifname="ios-utun", mtu=1600, service_key=svc_key)
        mux._on_local_tun_packet(dev, b"abc")
        return {
            "close_snapshot": {
                "closed": True,
                "chan_id": 7,
                "preferred_chan_id": None,
                "bound_chan_ids": [],
            },
            "local_snapshot": {
                "chan_id": dev.chan_id,
                "allocated_channel": True,
                "frames_hex": [frame.hex() for frame in mux.session.sent],
                "next_tun_id": mux._next_tun_id,
                "next_counter": mux._mux_counters[(dev.chan_id, ChannelMux.Proto.TUN)],
            },
            "local_spec": _service_spec_payload(local_spec),
            "open_payload_hex": payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_local_udp_server_datagram_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(11, "udp", "127.0.0.1", 5353, "udp", "127.0.0.1", 5353)
        svc_key = ("local", 0, 11)
        mux._local_services[svc_key] = spec

        class _FakeServerTransport:
            def get_extra_info(self, name):
                if name == "sockname":
                    return ("127.0.0.1", 5353)
                return None

        mux._svc_udp_servers[svc_key] = _FakeServerTransport()
        mux._on_local_udp_datagram(spec, svc_key, b"abc", ("127.0.0.1", 6000))
        chan = mux._udp_by_client[(svc_key, ("127.0.0.1", 6000))][0]
        return {
            "chan_id": chan,
            "allocated_channel": True,
            "frames_hex": [frame.hex() for frame in mux.session.sent],
            "next_udp_id": mux._next_udp_id,
            "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.UDP)],
            "spec": _service_spec_payload(spec),
            "service_key": "local:0:11",
            "addr_host": "127.0.0.1",
            "addr_port": 6000,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_local_udp_server_fragmented_datagram_summary() -> dict[str, object]:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(11, "udp", "127.0.0.1", 5353, "udp", "127.0.0.1", 5353)
        svc_key = ("local", 0, 11)
        mux._local_services[svc_key] = spec

        class _FakeServerTransport:
            def get_extra_info(self, name):
                if name == "sockname":
                    return ("127.0.0.1", 5353)
                return None

        mux._svc_udp_servers[svc_key] = _FakeServerTransport()
        mux._on_local_udp_datagram(spec, svc_key, bytes(index % 251 for index in range(180)), ("127.0.0.1", 6000))
        chan = mux._udp_by_client[(svc_key, ("127.0.0.1", 6000))][0]
        return {
            "chan_id": chan,
            "allocated_channel": True,
            "frames_hex": [frame.hex() for frame in mux.session.sent],
            "next_udp_id": mux._next_udp_id,
            "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.UDP)],
            "spec": _service_spec_payload(spec),
            "service_key": "local:0:11",
            "addr_host": "127.0.0.1",
            "addr_port": 6000,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_server_open_then_inbound_data_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    sent: list[tuple[bytes, tuple[str, int]]] = []
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(11, "udp", "127.0.0.1", 5353, "udp", "127.0.0.1", 5353)
        svc_key = ("local", 0, 11)
        mux._local_services[svc_key] = spec

        class _FakeServerTransport:
            def get_extra_info(self, name):
                if name == "sockname":
                    return ("127.0.0.1", 5353)
                return None

            def sendto(self, data, addr):
                sent.append((bytes(data), (addr[0], int(addr[1]))))

        mux._svc_udp_servers[svc_key] = _FakeServerTransport()
        mux._on_local_udp_datagram(spec, svc_key, b"abc", ("127.0.0.1", 6000))
        chan = mux._udp_by_client[(svc_key, ("127.0.0.1", 6000))][0]
        mux._rx_udp_data(chan, b"reply")
        return {
            "local_snapshot": {
                "chan_id": chan,
                "allocated_channel": True,
                "frames_hex": [frame.hex() for frame in mux.session.sent],
                "next_udp_id": mux._next_udp_id,
                "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.UDP)],
            },
            "inbound_snapshot": {
                "delivered": bool(sent),
                "packet_hex": sent[0][0].hex() if sent else None,
                "addr_host": sent[0][1][0] if sent else None,
                "addr_port": sent[0][1][1] if sent else None,
            },
            "spec": _service_spec_payload(spec),
            "service_key": "local:0:11",
            "addr_host": "127.0.0.1",
            "addr_port": 6000,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_server_open_then_inbound_fragment_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    sent: list[tuple[bytes, tuple[str, int]]] = []
    payload = bytes(index % 251 for index in range(180))
    datagram_id = 9
    chunks = [payload[0:70], payload[70:140], payload[140:180]]
    fragments = [
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 0) + chunks[0],
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 70) + chunks[1],
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 140) + chunks[2],
    ]
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(11, "udp", "127.0.0.1", 5353, "udp", "127.0.0.1", 5353)
        svc_key = ("local", 0, 11)
        mux._local_services[svc_key] = spec

        class _FakeServerTransport:
            def get_extra_info(self, name):
                if name == "sockname":
                    return ("127.0.0.1", 5353)
                return None

            def sendto(self, data, addr):
                sent.append((bytes(data), (addr[0], int(addr[1]))))

        mux._svc_udp_servers[svc_key] = _FakeServerTransport()
        mux._on_local_udp_datagram(spec, svc_key, b"abc", ("127.0.0.1", 6000))
        chan = mux._udp_by_client[(svc_key, ("127.0.0.1", 6000))][0]
        snapshots: list[dict[str, object]] = []
        received = 0
        for fragment in fragments:
            received += len(fragment) - ChannelMux.UDP_FRAG_HDR.size
            before = len(sent)
            mux._rx_udp_fragment(chan, fragment)
            snapshots.append(
                {
                    "delivered": len(sent) > before,
                    "packet_hex": sent[-1][0].hex() if len(sent) > before else None,
                    "addr_host": sent[-1][1][0] if len(sent) > before else None,
                    "addr_port": sent[-1][1][1] if len(sent) > before else None,
                    "datagram_id": datagram_id,
                    "total_len": len(payload),
                    "received_bytes": received,
                }
            )
        return {
            "local_snapshot": {
                "chan_id": chan,
                "allocated_channel": True,
                "frames_hex": [frame.hex() for frame in mux.session.sent],
                "next_udp_id": mux._next_udp_id,
                "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.UDP)],
            },
            "snapshots": snapshots,
            "fragments_hex": [fragment.hex() for fragment in fragments],
            "spec": _service_spec_payload(spec),
            "service_key": "local:0:11",
            "addr_host": "127.0.0.1",
            "addr_port": 6000,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_server_close_then_local_datagram_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(11, "udp", "127.0.0.1", 5353, "udp", "127.0.0.1", 5353)
        svc_key = ("local", 0, 11)
        mux._local_services[svc_key] = spec

        class _FakeServerTransport:
            def get_extra_info(self, name):
                if name == "sockname":
                    return ("127.0.0.1", 5353)
                return None

        mux._svc_udp_servers[svc_key] = _FakeServerTransport()
        mux._on_local_udp_datagram(spec, svc_key, b"abc", ("127.0.0.1", 6000))
        first_chan = mux._udp_by_client[(svc_key, ("127.0.0.1", 6000))][0]
        mux._rx_udp_close(first_chan)
        close_snapshot = {
            "closed": True,
            "chan_id": first_chan,
            "next_udp_id": mux._next_udp_id,
            "active_channels": sorted(mux._udp_by_chan.keys()),
        }
        mux._on_local_udp_datagram(spec, svc_key, b"abc", ("127.0.0.1", 6000))
        second_chan = mux._udp_by_client[(svc_key, ("127.0.0.1", 6000))][0]
        return {
            "close_snapshot": close_snapshot,
            "local_snapshot": {
                "chan_id": second_chan,
                "allocated_channel": True,
                "frames_hex": [frame.hex() for frame in mux.session.sent[2:]],
                "next_udp_id": mux._next_udp_id,
                "next_counter": mux._mux_counters[(second_chan, ChannelMux.Proto.UDP)],
            },
            "spec": _service_spec_payload(spec),
            "service_key": "local:0:11",
            "addr_host": "127.0.0.1",
            "addr_port": 6000,
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_client_open_then_connect_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 41
    transport = _FakeConnectedDatagramTransport(
        sockname=("0.0.0.0", 41041),
        peername=("127.0.0.1", 5353),
    )
    try:
        spec = ChannelMux.ServiceSpec(11, "udp", "0.0.0.0", 0, "udp", "127.0.0.1", 5353)
        payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_datagram_endpoint(factory, **kwargs):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_datagram_endpoint", side_effect=_fake_create_datagram_endpoint),
        ):
            mux._rx_udp_open(chan, payload, peer_id=0)
            open_snapshot = _python_udp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        connect_snapshot = _python_udp_client_connect_snapshot(
            mux,
            chan,
            transport,
            flushed_packets=[],
        )
        return {
            "open_snapshot": open_snapshot,
            "connect_snapshot": connect_snapshot,
            "open_payload_hex": payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_client_buffer_connect_then_data_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 41
    buffered_payload = b"early-client"
    immediate_payload = b"late-client"
    transport = _FakeConnectedDatagramTransport(
        sockname=("0.0.0.0", 41041),
        peername=("127.0.0.1", 5353),
    )
    try:
        spec = ChannelMux.ServiceSpec(11, "udp", "0.0.0.0", 0, "udp", "127.0.0.1", 5353)
        payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_datagram_endpoint(factory, **kwargs):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_datagram_endpoint", side_effect=_fake_create_datagram_endpoint),
        ):
            mux._rx_udp_open(chan, payload, peer_id=0)
            open_snapshot = _python_udp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux._rx_udp_data(chan, buffered_payload)
            buffered_snapshot = _python_udp_client_data_snapshot(
                mux=mux,
                chan=chan,
                transport=transport,
                buffered=True,
                dropped=False,
                sent_immediately=False,
                sent_packets=[],
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        connect_snapshot = _python_udp_client_connect_snapshot(
            mux,
            chan,
            transport,
            flushed_packets=[buffered_payload],
        )
        before_immediate = len(transport.frames)
        mux._rx_udp_data(chan, immediate_payload)
        immediate_snapshot = _python_udp_client_data_snapshot(
            mux=mux,
            chan=chan,
            transport=transport,
            buffered=False,
            dropped=False,
            sent_immediately=True,
            sent_packets=transport.frames[before_immediate:],
        )
        return {
            "open_snapshot": open_snapshot,
            "buffered_snapshot": buffered_snapshot,
            "connect_snapshot": connect_snapshot,
            "immediate_snapshot": immediate_snapshot,
            "open_payload_hex": payload.hex(),
            "buffered_hex": buffered_payload.hex(),
            "immediate_hex": immediate_payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_client_open_connect_then_local_datagram_summary() -> dict[str, object]:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    chan = 41
    payload = bytes(index % 251 for index in range(180))
    transport = _FakeConnectedDatagramTransport(
        sockname=("0.0.0.0", 41041),
        peername=("127.0.0.1", 5353),
    )
    try:
        spec = ChannelMux.ServiceSpec(11, "udp", "0.0.0.0", 0, "udp", "127.0.0.1", 5353)
        open_payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_datagram_endpoint(factory, **kwargs):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_datagram_endpoint", side_effect=_fake_create_datagram_endpoint),
        ):
            mux._rx_udp_open(chan, open_payload, peer_id=0)
            open_snapshot = _python_udp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        connect_snapshot = _python_udp_client_connect_snapshot(
            mux,
            chan,
            transport,
            flushed_packets=[],
        )
        protocol = mux._UDPClientProtocol(mux, chan)
        protocol.connection_made(transport)
        protocol.datagram_received(payload, transport.peername)
        return {
            "open_snapshot": open_snapshot,
            "connect_snapshot": connect_snapshot,
            "local_snapshot": {
                "frames_hex": [frame.hex() for frame in mux.session.sent],
                "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.UDP)],
                "next_fragment_datagram_id": mux._udp_frag_next_datagram_id,
            },
            "open_payload_hex": open_payload.hex(),
            "payload_hex": payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_client_open_connect_then_inbound_fragment_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 41
    payload = bytes(index % 251 for index in range(180))
    datagram_id = 9
    chunks = [payload[0:70], payload[70:140], payload[140:180]]
    fragments = [
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 0) + chunks[0],
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 70) + chunks[1],
        ChannelMux.UDP_FRAG_HDR.pack(datagram_id, len(payload), 140) + chunks[2],
    ]
    transport = _FakeConnectedDatagramTransport(
        sockname=("0.0.0.0", 41041),
        peername=("127.0.0.1", 5353),
    )
    try:
        spec = ChannelMux.ServiceSpec(11, "udp", "0.0.0.0", 0, "udp", "127.0.0.1", 5353)
        open_payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_datagram_endpoint(factory, **kwargs):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_datagram_endpoint", side_effect=_fake_create_datagram_endpoint),
        ):
            mux._rx_udp_open(chan, open_payload, peer_id=0)
            open_snapshot = _python_udp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        connect_snapshot = _python_udp_client_connect_snapshot(
            mux,
            chan,
            transport,
            flushed_packets=[],
        )
        snapshots: list[dict[str, object]] = []
        received = 0
        for fragment in fragments:
            received += len(fragment) - ChannelMux.UDP_FRAG_HDR.size
            before_frame_count = len(transport.frames)
            mux._rx_udp_fragment(chan, fragment)
            snapshots.append(
                _python_udp_client_fragment_snapshot(
                    mux=mux,
                    chan=chan,
                    transport=transport,
                    before_frame_count=before_frame_count,
                    datagram_id=datagram_id,
                    total_len=len(payload),
                    received_bytes=received,
                )
            )
        return {
            "open_snapshot": open_snapshot,
            "connect_snapshot": connect_snapshot,
            "snapshots": snapshots,
            "open_payload_hex": open_payload.hex(),
            "fragments_hex": [fragment.hex() for fragment in fragments],
        }
    finally:
        _close_mux(mux)


def _python_channelmux_udp_client_open_buffer_then_close_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 41
    buffered_payload = b"early-client"
    try:
        spec = ChannelMux.ServiceSpec(11, "udp", "0.0.0.0", 0, "udp", "127.0.0.1", 5353)
        payload = mux._build_open_v4(spec)
        scheduled_coroutines: list[object] = []

        def _track_task(coro):
            scheduled_coroutines.append(coro)
            return mock.Mock()

        with mock.patch.object(mux.loop, "create_task", side_effect=_track_task):
            mux._rx_udp_open(chan, payload, peer_id=0)
            open_snapshot = _python_udp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux._rx_udp_data(chan, buffered_payload)
            buffered_snapshot = _python_udp_client_data_snapshot(
                mux=mux,
                chan=chan,
                transport=_FakeConnectedDatagramTransport(sockname=("0.0.0.0", 0), peername=("127.0.0.1", 5353)),
                buffered=True,
                dropped=False,
                sent_immediately=False,
                sent_packets=[],
            )
        for coro in scheduled_coroutines:
            close_coro = getattr(coro, "close", None)
            if callable(close_coro):
                close_coro()
        mux._rx_udp_close(chan)
        return {
            "open_snapshot": open_snapshot,
            "buffered_snapshot": buffered_snapshot,
            "close_snapshot": _python_udp_client_close_snapshot(mux, chan),
            "open_payload_hex": payload.hex(),
            "buffered_hex": buffered_payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_client_open_then_connect_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 51
    transport = _FakeTCPTransport(
        sockname=("127.0.0.1", 51051),
        peername=("127.0.0.1", 8080),
    )
    try:
        spec = ChannelMux.ServiceSpec(21, "tcp", "0.0.0.0", 0, "tcp", "127.0.0.1", 8080)
        payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            name = getattr(getattr(coro, "cr_code", None), "co_name", "")
            if name == "_rx":
                coro.close()
                return mock.Mock()
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_connection(factory, host, port):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_connection", side_effect=_fake_create_connection),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
        ):
            mux._rx_tcp_open(chan, payload, peer_id=0)
            open_snapshot = _python_tcp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        return {
            "open_snapshot": open_snapshot,
            "connect_snapshot": _python_tcp_client_connect_snapshot(
                mux,
                chan,
                transport,
                flushed_buffers=[],
            ),
            "open_payload_hex": payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_client_buffer_connect_then_data_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 51
    buffered_payload = b"early-tcp"
    immediate_payload = b"late-tcp"
    transport = _FakeTCPTransport(
        sockname=("127.0.0.1", 51051),
        peername=("127.0.0.1", 8080),
    )
    try:
        spec = ChannelMux.ServiceSpec(21, "tcp", "0.0.0.0", 0, "tcp", "127.0.0.1", 8080)
        payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            name = getattr(getattr(coro, "cr_code", None), "co_name", "")
            if name == "_rx":
                coro.close()
                return mock.Mock()
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_connection(factory, host, port):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_connection", side_effect=_fake_create_connection),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
        ):
            mux._rx_tcp_open(chan, payload, peer_id=0)
            open_snapshot = _python_tcp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux._rx_tcp(chan, ChannelMux.MType.DATA, buffered_payload)
            buffered_snapshot = _python_tcp_client_data_snapshot(
                mux=mux,
                chan=chan,
                buffered=True,
                sent_immediately=False,
                written_buffers=[],
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        connect_snapshot = _python_tcp_client_connect_snapshot(
            mux,
            chan,
            transport,
            flushed_buffers=[buffered_payload],
        )
        before_immediate = len(transport.written)
        mux._rx_tcp(chan, ChannelMux.MType.DATA, immediate_payload)
        immediate_snapshot = _python_tcp_client_data_snapshot(
            mux=mux,
            chan=chan,
            buffered=False,
            sent_immediately=True,
            written_buffers=transport.written[before_immediate:],
        )
        return {
            "open_snapshot": open_snapshot,
            "buffered_snapshot": buffered_snapshot,
            "connect_snapshot": connect_snapshot,
            "immediate_snapshot": immediate_snapshot,
            "open_payload_hex": payload.hex(),
            "buffered_hex": buffered_payload.hex(),
            "immediate_hex": immediate_payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_client_open_connect_then_local_data_summary() -> dict[str, object]:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    chan = 51
    payload = bytes(index % 251 for index in range(64))
    transport = _FakeTCPTransport(
        sockname=("127.0.0.1", 51051),
        peername=("127.0.0.1", 8080),
    )
    try:
        spec = ChannelMux.ServiceSpec(21, "tcp", "0.0.0.0", 0, "tcp", "127.0.0.1", 8080)
        open_payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            name = getattr(getattr(coro, "cr_code", None), "co_name", "")
            if name == "_rx":
                coro.close()
                return mock.Mock()
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_connection(factory, host, port):
            protocol = factory()
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_connection", side_effect=_fake_create_connection),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
            mock.patch.object(mux, "_schedule_service_hook", return_value=None),
        ):
            mux._rx_tcp_open(chan, open_payload, peer_id=0)
            open_snapshot = _python_tcp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        connect_snapshot = _python_tcp_client_connect_snapshot(
            mux,
            chan,
            transport,
            flushed_buffers=[],
        )
        mux._send_mux(chan, ChannelMux.Proto.TCP, ChannelMux.MType.DATA, payload)
        return {
            "open_snapshot": open_snapshot,
            "connect_snapshot": connect_snapshot,
            "local_snapshot": {
                "frames_hex": [frame.hex() for frame in mux.session.sent],
                "next_counter": mux._mux_counters[(chan, ChannelMux.Proto.TCP)],
            },
            "open_payload_hex": open_payload.hex(),
            "payload_hex": payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_client_open_buffer_then_close_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 51
    buffered_payload = b"early-tcp"
    try:
        spec = ChannelMux.ServiceSpec(21, "tcp", "0.0.0.0", 0, "tcp", "127.0.0.1", 8080)
        payload = mux._build_open_v4(spec)
        scheduled_coroutines: list[object] = []

        def _track_task(coro):
            scheduled_coroutines.append(coro)
            return mock.Mock()

        with mock.patch.object(mux.loop, "create_task", side_effect=_track_task):
            mux._rx_tcp_open(chan, payload, peer_id=0)
            open_snapshot = _python_tcp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux._rx_tcp(chan, ChannelMux.MType.DATA, buffered_payload)
            buffered_snapshot = _python_tcp_client_data_snapshot(
                mux=mux,
                chan=chan,
                buffered=True,
                sent_immediately=False,
                written_buffers=[],
            )
        for coro in scheduled_coroutines:
            close_coro = getattr(coro, "close", None)
            if callable(close_coro):
                close_coro()
        mux._rx_tcp(chan, ChannelMux.MType.CLOSE, b"")
        return {
            "open_snapshot": open_snapshot,
            "buffered_snapshot": buffered_snapshot,
            "close_snapshot": _python_tcp_client_close_snapshot(mux, chan),
            "open_payload_hex": payload.hex(),
            "buffered_hex": buffered_payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_client_open_then_local_eof_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    chan = 51
    transport = _FakeTCPTransport(
        sockname=("127.0.0.1", 51051),
        peername=("127.0.0.1", 8080),
    )
    try:
        spec = ChannelMux.ServiceSpec(21, "tcp", "0.0.0.0", 0, "tcp", "127.0.0.1", 8080)
        open_payload = mux._build_open_v4(spec)
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task
        protocol_holder: dict[str, asyncio.StreamReaderProtocol] = {}

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        async def _fake_create_connection(factory, host, port):
            protocol = factory()
            protocol_holder["protocol"] = protocol
            protocol.connection_made(transport)
            return transport, protocol

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux.loop, "create_connection", side_effect=_fake_create_connection),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
            mock.patch.object(mux, "_schedule_service_hook", return_value=None),
        ):
            mux._rx_tcp_open(chan, open_payload, peer_id=0)
            open_snapshot = _python_tcp_client_open_snapshot(
                mux,
                chan,
                connect_requested=True,
                connected=False,
            )
            mux.loop.run_until_complete(tasks[0])
            protocol = protocol_holder["protocol"]
            connect_snapshot = _python_tcp_client_connect_snapshot(
                mux,
                chan,
                transport,
                flushed_buffers=[],
            )
            before_close = len(mux.session.sent)
            protocol.eof_received()
            protocol.connection_lost(None)
            mux.loop.run_until_complete(tasks[1])
        return {
            "open_snapshot": open_snapshot,
            "connect_snapshot": connect_snapshot,
            "close_snapshot": _python_tcp_client_local_close_snapshot(
                mux,
                chan,
                mux.session.sent[before_close:],
            ),
            "open_payload_hex": open_payload.hex(),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_server_accept_then_local_data_then_eof_summary() -> dict[str, object]:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    payload = bytes(index % 251 for index in range(64))
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(31, "tcp", "127.0.0.1", 8080, "tcp", "127.0.0.1", 8080)
        svc_key = ("local", 0, 31)
        handler = _start_fake_tcp_server(mux, spec, svc_key)
        reader = _ControllableAsyncReader(mux.loop, [])
        writer = _FakeTCPStreamWriter(
            _FakeTCPTransport(sockname=("127.0.0.1", 8080), peername=("127.0.0.1", 61000))
        )
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
            mock.patch.object(mux, "_schedule_service_hook", return_value=None),
        ):
            mux.loop.run_until_complete(handler(reader, writer))
            chan = next(iter(mux._tcp_by_chan))
            accept_snapshot = _python_tcp_server_accept_snapshot(mux, chan)
            pre_data_frames = len(mux.session.sent)
            reader.feed_data(payload)
            mux.loop.run_until_complete(asyncio.sleep(0))
            data_snapshot = _python_tcp_server_data_snapshot(mux, chan, mux.session.sent[pre_data_frames:])
            reader.feed_eof()
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        return {
            "accept_snapshot": accept_snapshot,
            "data_snapshot": data_snapshot,
            "close_snapshot": _python_tcp_server_close_snapshot(mux, chan, mux.session.sent[-1:]),
            "spec": _service_spec_payload(spec),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_server_accept_then_inbound_data_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(31, "tcp", "127.0.0.1", 8080, "tcp", "127.0.0.1", 8080)
        svc_key = ("local", 0, 31)
        handler = _start_fake_tcp_server(mux, spec, svc_key)
        reader = _ControllableAsyncReader(mux.loop, [])
        writer = _FakeTCPStreamWriter(
            _FakeTCPTransport(sockname=("127.0.0.1", 8080), peername=("127.0.0.1", 61000))
        )
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
            mock.patch.object(mux, "_schedule_service_hook", return_value=None),
        ):
            mux.loop.run_until_complete(handler(reader, writer))
            chan = next(iter(mux._tcp_by_chan))
            accept_snapshot = _python_tcp_server_accept_snapshot(mux, chan)
            mux._rx_tcp(chan, ChannelMux.MType.DATA, b"reply")
            inbound_snapshot = _python_tcp_server_inbound_snapshot(writer)
            reader.feed_eof()
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        mux._rx_tcp(chan, ChannelMux.MType.CLOSE, b"")
        return {
            "accept_snapshot": accept_snapshot,
            "inbound_snapshot": inbound_snapshot,
            "spec": _service_spec_payload(spec),
        }
    finally:
        _close_mux(mux)


def _python_channelmux_tcp_server_accept_then_inbound_close_summary() -> dict[str, object]:
    mux = _make_mux(connected=True)
    try:
        mux._overlay_connected = True
        mux._accepting_enabled = True
        spec = ChannelMux.ServiceSpec(31, "tcp", "127.0.0.1", 8080, "tcp", "127.0.0.1", 8080)
        svc_key = ("local", 0, 31)
        handler = _start_fake_tcp_server(mux, spec, svc_key)
        reader = _ControllableAsyncReader(mux.loop, [])
        writer = _FakeTCPStreamWriter(
            _FakeTCPTransport(sockname=("127.0.0.1", 8080), peername=("127.0.0.1", 61000))
        )
        tasks: list[asyncio.Task[object]] = []
        original_create_task = mux.loop.create_task

        def _track_task(coro):
            task = original_create_task(coro)
            tasks.append(task)
            return task

        with (
            mock.patch.object(mux.loop, "create_task", side_effect=_track_task),
            mock.patch.object(mux, "_ensure_backpressure_task", return_value=None),
            mock.patch.object(mux, "_schedule_service_hook", return_value=None),
        ):
            mux.loop.run_until_complete(handler(reader, writer))
            chan = next(iter(mux._tcp_by_chan))
            accept_snapshot = _python_tcp_server_accept_snapshot(mux, chan)
            mux._rx_tcp(chan, ChannelMux.MType.CLOSE, b"")
            close_snapshot = _python_tcp_server_close_snapshot(mux, chan, [])
            reader.feed_eof()
            mux.loop.run_until_complete(asyncio.gather(*tasks))
        return {
            "accept_snapshot": accept_snapshot,
            "close_snapshot": close_snapshot,
            "writer_closed": writer.transport.closed,
            "spec": _service_spec_payload(spec),
        }
    finally:
        _close_mux(mux)


def _captured_control_policy_inbound(
    *,
    expected: int,
    missing: set[int],
    grew_missing: bool,
    now_ns: int,
    rtt_est_ms: float,
    last_sent_last_in_order: int,
    last_control_sent_ns: int,
    established_ns: int,
) -> str | None:
    session = Session(proto=Protocol(BaseFrameV2))
    session.expected = expected
    session.missing = set(missing)
    session.proto.rtt_est_ms = rtt_est_ms
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto._last_sent_last_in_order = last_sent_last_in_order
    proto._last_control_sent_ns = last_control_sent_ns
    proto._established_ns = established_ns
    reasons: list[str] = []
    proto._emit_control = lambda _now_t, reason="timer_paced": reasons.append(reason)  # type: ignore[method-assign]
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        proto._evaluate_control_policy_inbound(grew_missing)
    return reasons[0] if reasons else None


def _captured_control_policy_timer(
    *,
    expected: int,
    missing: set[int],
    now_ns: int,
    rtt_est_ms: float,
    last_sent_last_in_order: int,
    last_control_sent_ns: int,
    established_ns: int,
) -> str | None:
    session = Session(proto=Protocol(BaseFrameV2))
    session.expected = expected
    session.missing = set(missing)
    session.proto.rtt_est_ms = rtt_est_ms
    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto._last_sent_last_in_order = last_sent_last_in_order
    proto._last_control_sent_ns = last_control_sent_ns
    proto._established_ns = established_ns
    reasons: list[str] = []
    proto._emit_control = lambda _now_t, reason="timer_paced": reasons.append(reason)  # type: ignore[method-assign]
    with mock.patch.object(myudp, "now_ns", return_value=now_ns):
        proto._evaluate_control_policy_timer()
    return reasons[0] if reasons else None


def test_python_mux_pack_and_unpack_guard_roundtrip() -> None:
    mux = _make_mux()
    try:
        payload = bytes.fromhex("000102deadbeef")
        wire = mux._pack_mux(17, ChannelMux.Proto.TCP, 0x1FFFE, ChannelMux.MType.OPEN, payload)
        parsed = mux._unpack_mux(wire)
        assert parsed is not None
        chan_id, proto, counter, mtype, body = parsed
        assert chan_id == 17
        assert proto == ChannelMux.Proto.TCP
        assert counter == 0xFFFE
        assert mtype == ChannelMux.MType.OPEN
        assert bytes(body) == payload
    finally:
        _close_mux(mux)


def test_python_mux_unpack_rejects_truncated_payload_guard() -> None:
    mux = _make_mux()
    try:
        payload = mux._pack_mux(3, ChannelMux.Proto.UDP, 7, ChannelMux.MType.DATA, b"hello")
        assert mux._unpack_mux(payload[:-1]) is None
    finally:
        _close_mux(mux)


def test_python_control_chunk_roundtrip_guard() -> None:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    try:
        payload = bytes(index % 251 for index in range(240))
        mux._send_chunked_control_payload(
            chan_id=17,
            proto=ChannelMux.Proto.TCP,
            chunk_mtype=ChannelMux.MType.OPEN_CHUNK,
            payload=payload,
        )
        frames: list[bytes] = []
        for wire in mux.session.sent:
            parsed = mux._unpack_mux(wire)
            assert parsed is not None
            chan_id, proto, _counter, mtype, body = parsed
            assert chan_id == 17
            assert proto == ChannelMux.Proto.TCP
            assert mtype == ChannelMux.MType.OPEN_CHUNK
            frames.append(bytes(body))
        assert len(frames) >= 2

        assembled = None
        for frame in frames:
            assembled = mux._consume_control_chunk(
                chan_id=17,
                proto=ChannelMux.Proto.TCP,
                mtype=ChannelMux.MType.OPEN_CHUNK,
                payload=frame,
                peer_id=7,
            ) or assembled
        assert assembled == payload
    finally:
        _close_mux(mux)


def test_python_udp_data_frame_guard_roundtrip() -> None:
    protocol = _make_udp_protocol()
    with mock.patch.object(myudp, "now_ns", return_value=1234567890123456789):
        frame = DataPacket.build_full(7, FRAME_CONT, 5, b"hello")
    parsed_protocol = protocol.parse_frame_with_times(frame.raw)
    assert parsed_protocol is not None
    assert parsed_protocol[0] == myudp.PTYPE_DATA
    assert parsed_protocol[2] == 1234567890123456789
    assert parsed_protocol[3] == 0
    parsed_packet = DataPacket.parse_full(frame.raw)
    assert parsed_packet is not None
    assert parsed_packet.pkt_counter == 7
    assert parsed_packet.frame_type == FRAME_CONT
    assert parsed_packet.len_or_offset == 5
    assert parsed_packet.data == b"hello"


def test_python_udp_control_frame_guard_roundtrip() -> None:
    protocol = _make_udp_protocol()
    with mock.patch.object(myudp, "now_ns", return_value=987654321000000000):
        frame = ControlPacket.build_full(4, 9, [5, 7])
    parsed_protocol = protocol.parse_frame_with_times(frame.raw)
    assert parsed_protocol is not None
    assert parsed_protocol[0] == myudp.PTYPE_CONTROL
    assert parsed_protocol[2] == 987654321000000000
    parsed_packet = ControlPacket.parse_full(frame.raw)
    assert parsed_packet is not None
    assert parsed_packet.last_in_order_rx == 4
    assert parsed_packet.highest_rx == 9
    assert parsed_packet.missed == [5, 7]


def test_python_udp_session_segmentation_guard() -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    payload = bytes(index % 251 for index in range((myudp.DATA_MAX_CHUNK * 2) + 17))
    with mock.patch.object(myudp, "now_ns", return_value=1111):
        produced = session.send_application_payload(payload, transport)
    assert produced == 3
    parsed = [DataPacket.parse_full(frame) for frame in transport.frames]
    assert [pkt.pkt_counter for pkt in parsed if pkt is not None] == [1, 2, 3]


def test_python_udp_session_gap_reassembly_guard() -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    with mock.patch.object(myudp, "now_ns", return_value=2000):
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
        pkt1 = DataPacket.build_full(1, FRAME_FIRST, 9, b"abc")
    advanced, completed = session.process_data(pkt2)
    assert advanced is False
    assert completed == []
    advanced, completed = session.process_data(pkt3)
    assert advanced is False
    assert completed == []
    advanced, completed = session.process_data(pkt1)
    assert advanced is True
    assert completed == [b"abcdefghi"]
    assert session.expected == 4
    assert session.pending == {}
    assert session.missing == set()


def test_python_udp_session_build_control_guard() -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    with mock.patch.object(myudp, "now_ns", return_value=3000):
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
    session.process_data(pkt2)
    session.process_data(pkt3)
    with mock.patch.object(myudp, "now_ns", return_value=3333):
        control = session.build_control()
    assert control.last_in_order_rx == 0
    assert control.highest_rx == 3
    assert control.missed == [1]


def test_python_udp_control_policy_guard_inbound_grew_missing() -> None:
    reason = _captured_control_policy_inbound(
        expected=2,
        missing={4},
        grew_missing=True,
        now_ns=1_000_000,
        rtt_est_ms=100.0,
        last_sent_last_in_order=0,
        last_control_sent_ns=0,
        established_ns=0,
    )
    assert reason == "inbound_grew_missing"


def test_python_udp_retransmit_due_to_control_guard() -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)

    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport
    feedback = ControlPacket.build_full(0, 2, [2])
    session.confirm_with_feedback(feedback.last_in_order_rx, feedback.highest_rx, feedback.missed)
    proto._schedule_retrans(feedback.missed)

    retransmitted = DataPacket.parse_full(transport.frames[-1])
    assert retransmitted is not None
    assert retransmitted.pkt_counter == 2
    assert session.send_attempts[2] == 2


def test_python_udp_unconfirmed_retransmit_guard() -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)

    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport
    session.proto.rtt_est_ms = 100.0
    sweep_now_ns = max(session.send_txns.values()) + 200_000_000
    with mock.patch.object(myudp, "now_ns", return_value=sweep_now_ns):
        proto._retx_sweep_unconfirmed()

    assert len(transport.frames) == 4
    assert session.send_attempts[1] == 2
    assert session.send_attempts[2] == 2


def test_python_udp_inbound_control_summary_guard() -> None:
    summary = _python_inbound_control_summary(
        send_port_present=True,
        packet_last_in_order=0,
        packet_highest=2,
        packet_missed=[2],
    )
    assert summary["emitted_counters"] == [2]
    assert summary["flush_requested"] is True
    assert summary["control_should_emit"] is False


def test_python_udp_inbound_idle_summary_guard() -> None:
    summary = _python_inbound_idle_summary(
        send_port_present=True,
        tx_ns=5_000,
        echo_ns=0,
        now_ns=6_000,
    )
    assert summary["reflected"] is True
    assert summary["reflected_frame_hex"] is not None


def test_python_udp_inbound_data_summary_guard() -> None:
    with mock.patch.object(myudp, "now_ns", return_value=2_000):
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
        pkt1 = DataPacket.build_full(1, FRAME_FIRST, 9, b"abc")
    summary = _python_inbound_data_summary(
        pre_frames=[pkt2.raw, pkt3.raw],
        frame=pkt1.raw,
        tx_ns=2_000,
        echo_ns=0,
        now_ns=3_000,
        send_port_present=True,
        last_sent_last_in_order=3,
        last_control_sent_ns=0,
        established_ns=0,
        prior_rtt_est_ms=0.0,
        prior_transmit_delay_est_ms=0.0,
    )
    assert summary["control_reasons"] == ["gap_filled_ack"]
    assert summary["completed_hex"] == [b"abcdefghi".hex()]


def test_swift_mux_pack_parity(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        body = bytes.fromhex("00112233aa55")
        python_wire = mux._pack_mux(29, ChannelMux.Proto.UDP, 65537, ChannelMux.MType.DATA_FRAG, body)
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "pack_mux",
                "chan_id": 29,
                "proto": "udp",
                "counter": 65537,
                "mtype": "data_frag",
                "data_hex": body.hex(),
            },
        )
        assert swift["hex"] == python_wire.hex()
    finally:
        _close_mux(mux)


def test_swift_mux_unpack_parity(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        wire = mux._pack_mux(41, ChannelMux.Proto.TUN, 513, ChannelMux.MType.CLOSE, b"tun")
        python_parsed = mux._unpack_mux(wire)
        assert python_parsed is not None
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "unpack_mux",
                "wire_hex": wire.hex(),
            },
        )
        assert swift["frame"] == {
            "chan_id": python_parsed[0],
            "proto": int(python_parsed[1]),
            "counter": python_parsed[2],
            "mtype": int(python_parsed[3]),
            "data_hex": bytes(python_parsed[4]).hex(),
        }
    finally:
        _close_mux(mux)


def test_swift_control_chunk_payload_exact_bytes(swift_channelmux_runner: Path) -> None:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    try:
        payload = bytes(index % 239 for index in range(260))
        mux._ctrl_chunk_next_txid = 9
        mux._send_chunked_control_payload(
            chan_id=0,
            proto=ChannelMux.Proto.UDP,
            chunk_mtype=ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK,
            payload=payload,
        )
        python_frames: list[str] = []
        for wire in mux.session.sent:
            parsed = mux._unpack_mux(wire)
            assert parsed is not None
            _chan_id, proto, _counter, mtype, body = parsed
            assert proto == ChannelMux.Proto.UDP
            assert mtype == ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK
            python_frames.append(bytes(body).hex())

        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "chunk_control_payload",
                "txid": 9,
                "max_app_payload": 96,
                "payload_hex": payload.hex(),
            },
        )
        assert swift["frames_hex"] == python_frames
    finally:
        _close_mux(mux)


def test_swift_udp_protocol_frame_exact_bytes(swift_channelmux_runner: Path) -> None:
    protocol = _make_udp_protocol()
    protocol._last_rx_tx_ns = 200
    protocol._last_rx_wall_ns = 850
    with mock.patch.object(myudp, "now_ns", return_value=1000):
        python_frame = protocol.build_frame(myudp.PTYPE_DATA, b"payload", initial=False)
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "build_udp_protocol_frame",
            "ptype": myudp.PTYPE_DATA,
            "tx_ns": 1000,
            "echo_ns": 350,
            "payload_hex": b"payload".hex(),
        },
    )
    assert swift["hex"] == python_frame.hex()


def test_swift_udp_protocol_parse_matches_python(swift_channelmux_runner: Path) -> None:
    protocol = _make_udp_protocol()
    with mock.patch.object(myudp, "now_ns", return_value=2000):
        python_frame = protocol.build_frame(myudp.PTYPE_CONTROL, b"abc", initial=True)
    python_parsed = protocol.parse_frame_with_times(python_frame)
    assert python_parsed is not None
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "parse_udp_protocol_frame",
            "frame_hex": python_frame.hex(),
        },
    )
    assert swift["frame"] == {
        "ptype": python_parsed[0],
        "payload_hex": bytes(python_parsed[1]).hex(),
        "tx_ns": str(python_parsed[2]),
        "echo_ns": str(python_parsed[3]),
    }


def test_swift_udp_data_frame_exact_bytes(swift_channelmux_runner: Path) -> None:
    with mock.patch.object(myudp, "now_ns", return_value=4444):
        python_frame = DataPacket.build_full(11, FRAME_FIRST, 9, b"abcdef")
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "build_udp_data_frame",
            "pkt_counter": 11,
            "frame_type": FRAME_FIRST,
            "len_or_offset": 9,
            "payload_hex": b"abcdef".hex(),
            "tx_ns": 4444,
            "echo_ns": 0,
        },
    )
    assert swift["hex"] == python_frame.raw.hex()


def test_swift_udp_data_frame_parse_matches_python(swift_channelmux_runner: Path) -> None:
    with mock.patch.object(myudp, "now_ns", return_value=5555):
        python_frame = DataPacket.build_full(12, FRAME_CONT, 3, b"def")
    python_parsed = DataPacket.parse_full(python_frame.raw)
    assert python_parsed is not None
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "parse_udp_data_frame",
            "frame_hex": python_frame.raw.hex(),
        },
    )
    assert swift["packet"] == {
        "pkt_counter": python_parsed.pkt_counter,
        "frame_type": python_parsed.frame_type,
        "len_or_offset": python_parsed.len_or_offset,
        "chunk_len": python_parsed.chunk_len,
        "data_hex": python_parsed.data.hex(),
    }


def test_swift_udp_control_frame_exact_bytes(swift_channelmux_runner: Path) -> None:
    with mock.patch.object(myudp, "now_ns", return_value=7777):
        python_frame = ControlPacket.build_full(8, 13, [9, 11, 12])
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "build_udp_control_frame",
            "last_in_order_rx": 8,
            "highest_rx": 13,
            "missed": [9, 11, 12],
            "tx_ns": 7777,
            "echo_ns": 0,
        },
    )
    assert swift["hex"] == python_frame.raw.hex()


def test_swift_udp_control_frame_parse_matches_python(swift_channelmux_runner: Path) -> None:
    with mock.patch.object(myudp, "now_ns", return_value=8888):
        python_frame = ControlPacket.build_full(10, 15, [11, 12])
    python_parsed = ControlPacket.parse_full(python_frame.raw)
    assert python_parsed is not None
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "parse_udp_control_frame",
            "frame_hex": python_frame.raw.hex(),
        },
    )
    assert swift["packet"] == {
        "last_in_order_rx": python_parsed.last_in_order_rx,
        "highest_rx": python_parsed.highest_rx,
        "missed": python_parsed.missed,
    }


def test_swift_udp_session_segmentation_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    payload = bytes(index % 251 for index in range((myudp.DATA_MAX_CHUNK * 2) + 17))
    with mock.patch.object(myudp, "now_ns", return_value=1234):
        produced = session.send_application_payload(payload, transport)
    assert produced == 3
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "segment_udp_payload",
            "payload_hex": payload.hex(),
            "tx_ns": 1234,
            "echo_ns": 0,
            "starting_counter": 1,
        },
    )
    assert swift["frames_hex"] == [frame.hex() for frame in transport.frames]


def test_swift_udp_session_reassembly_matches_python(swift_channelmux_runner: Path) -> None:
    with mock.patch.object(myudp, "now_ns", return_value=2345):
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
        pkt1 = DataPacket.build_full(1, FRAME_FIRST, 9, b"abc")
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "reassemble_udp_payloads",
            "frames_hex": [pkt2.raw.hex(), pkt3.raw.hex(), pkt1.raw.hex()],
        },
    )
    assert swift["completed_hex"] == [b"abcdefghi".hex()]
    assert swift["expected"] == 4
    assert swift["pending"] == []
    assert swift["missing"] == []


def test_swift_udp_session_build_control_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    with mock.patch.object(myudp, "now_ns", return_value=3000):
        pkt2 = DataPacket.build_full(2, FRAME_CONT, 3, b"def")
        pkt3 = DataPacket.build_full(3, FRAME_CONT, 6, b"ghi")
    session.process_data(pkt2)
    session.process_data(pkt3)
    with mock.patch.object(myudp, "now_ns", return_value=3333):
        python_control = session.build_control()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "build_udp_session_control",
            "expected": session.expected,
            "pending": sorted(session.pending),
            "missing": sorted(session.missing),
            "tx_ns": 3333,
            "echo_ns": 0,
        },
    )
    assert swift["hex"] == python_control.raw.hex()
    assert swift["packet"] == {
        "last_in_order_rx": python_control.last_in_order_rx,
        "highest_rx": python_control.highest_rx,
        "missed": python_control.missed,
    }


def test_swift_udp_session_confirm_feedback_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    with mock.patch.object(myudp, "now_ns", return_value=4444):
        session.send_application_payload(b"one", transport)
        session.send_application_payload(b"two", transport)
        session.send_application_payload(b"three", transport)

    feedback_steps = [
        {"last_in_order": 0, "highest": 3, "missed": [2]},
        {"last_in_order": 0, "highest": 3, "missed": []},
        {"last_in_order": 3, "highest": 3, "missed": []},
    ]

    swift_state = {
        "send_buffer": sorted(session.send_buf),
        "peer_reported_missing": sorted(session.peer_reported_missing),
    }

    for step in feedback_steps:
        session.confirm_with_feedback(step["last_in_order"], step["highest"], step["missed"])
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "confirm_udp_feedback",
                "send_buffer": swift_state["send_buffer"],
                "peer_reported_missing": swift_state["peer_reported_missing"],
                "last_in_order": step["last_in_order"],
                "highest": step["highest"],
                "missed": step["missed"],
            },
        )
        assert swift["send_buffer"] == sorted(session.send_buf)
        assert swift["peer_reported_missing"] == sorted(session.peer_reported_missing)
        assert swift["last_ack_peer"] == session.last_ack_peer
        swift_state = {
            "send_buffer": swift["send_buffer"],
            "peer_reported_missing": swift["peer_reported_missing"],
        }


@pytest.mark.parametrize(
    ("policy_request", "python_reason"),
    [
        (
            {
                "now_ns": 1_000_000,
                "expected": 2,
                "missing_count": 1,
                "grew_missing": True,
                "last_sent_last_in_order": 0,
                "last_control_sent_ns": 0,
                "established_ns": 0,
                "rtt_est_ms": 100.0,
            },
            "inbound_grew_missing",
        ),
        (
            {
                "now_ns": 1_060_000_000,
                "expected": 3,
                "missing_count": 0,
                "grew_missing": False,
                "last_sent_last_in_order": 1,
                "last_control_sent_ns": 0,
                "established_ns": 1_000_000_000,
                "rtt_est_ms": 100.0,
            },
            "advanced_in_order",
        ),
        (
            {
                "now_ns": 1_010_000_000,
                "expected": 3,
                "missing_count": 0,
                "grew_missing": False,
                "last_sent_last_in_order": 1,
                "last_control_sent_ns": 0,
                "established_ns": 1_000_000_000,
                "rtt_est_ms": 100.0,
            },
            None,
        ),
    ],
)
def test_swift_udp_control_policy_inbound_matches_python(
    swift_channelmux_runner: Path,
    policy_request: dict[str, object],
    python_reason: str | None,
) -> None:
    python_result = _captured_control_policy_inbound(
        expected=policy_request["expected"],
        missing=set(range(1, int(policy_request["missing_count"]) + 1)),
        grew_missing=policy_request["grew_missing"],
        now_ns=policy_request["now_ns"],
        rtt_est_ms=policy_request["rtt_est_ms"],
        last_sent_last_in_order=policy_request["last_sent_last_in_order"],
        last_control_sent_ns=policy_request["last_control_sent_ns"],
        established_ns=policy_request["established_ns"],
    )
    assert python_result == python_reason
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "evaluate_udp_control_policy_inbound", **policy_request},
    )
    assert swift == {
        "should_emit": python_reason is not None,
        "reason": python_reason,
    }


@pytest.mark.parametrize(
    ("policy_request", "python_reason"),
    [
        (
            {
                "now_ns": 2_020_000_000,
                "expected": 4,
                "missing_count": 0,
                "last_sent_last_in_order": 2,
                "last_control_sent_ns": 0,
                "established_ns": 2_000_000_000,
                "rtt_est_ms": 100.0,
            },
            None,
        ),
        (
            {
                "now_ns": 2_060_000_000,
                "expected": 4,
                "missing_count": 0,
                "last_sent_last_in_order": 2,
                "last_control_sent_ns": 0,
                "established_ns": 2_000_000_000,
                "rtt_est_ms": 100.0,
            },
            "timer_paced_clear_miss",
        ),
        (
            {
                "now_ns": 3_060_000_000,
                "expected": 4,
                "missing_count": 2,
                "last_sent_last_in_order": 2,
                "last_control_sent_ns": 3_000_000_000,
                "established_ns": 2_000_000_000,
                "rtt_est_ms": 100.0,
            },
            "timer_paced_with_missing",
        ),
    ],
)
def test_swift_udp_control_policy_timer_matches_python(
    swift_channelmux_runner: Path,
    policy_request: dict[str, object],
    python_reason: str | None,
) -> None:
    python_result = _captured_control_policy_timer(
        expected=policy_request["expected"],
        missing=set(range(1, int(policy_request["missing_count"]) + 1)),
        now_ns=policy_request["now_ns"],
        rtt_est_ms=policy_request["rtt_est_ms"],
        last_sent_last_in_order=policy_request["last_sent_last_in_order"],
        last_control_sent_ns=policy_request["last_control_sent_ns"],
        established_ns=policy_request["established_ns"],
    )
    assert python_result == python_reason
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "evaluate_udp_control_policy_timer", **policy_request},
    )
    assert swift == {
        "should_emit": python_reason is not None,
        "reason": python_reason,
    }


def test_swift_udp_retrans_due_to_control_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)
    original_second = transport.frames[1]
    parsed_original = session.proto.parse_frame_with_times(original_second)
    assert parsed_original is not None
    retrans_now_ns = parsed_original[2] + 150_000_000

    session.proto.on_frame_received(10_000_000_000, retrans_now_ns - 1_000_000)

    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport
    feedback = ControlPacket.build_full(0, 2, [2])
    session.confirm_with_feedback(feedback.last_in_order_rx, feedback.highest_rx, feedback.missed)
    with mock.patch.object(myudp, "now_ns", return_value=retrans_now_ns):
        proto._schedule_retrans(feedback.missed)

    python_frame = transport.frames[-1]
    python_parsed = session.proto.parse_frame_with_times(python_frame)
    assert python_parsed is not None
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "schedule_udp_retrans_due_to_control",
            "now_ns": retrans_now_ns,
            "missed": [2],
            "rtt_est_ms": session.proto.rtt_est_ms,
            "send_buffer": sorted(session.send_buf),
            "send_meta": _send_meta_payload(session),
            "send_tx_ns": _int_keyed_map(session.send_txns),
            "last_retx_ns": _int_keyed_map({}),
            "send_attempts": _int_keyed_map({1: 1, 2: 1}),
            "peer_reported_missing": sorted(session.peer_reported_missing),
            "last_send_ns": session.send_txns[2],
            "last_rx_tx_ns": 10_000_000_000,
            "last_rx_wall_ns": retrans_now_ns - 1_000_000,
        },
    )
    assert swift["emitted_counters"] == [2]
    assert swift["frames_hex"] == [python_frame.hex()]
    assert swift["send_attempts"] == {"1": 1, "2": 2}
    assert swift["peer_missed_count"] == 1
    assert swift["last_send_ns"] == str(retrans_now_ns)
    assert python_frame != original_second
    assert python_parsed[2] > session.send_txns[2]
    assert python_parsed[3] > 0


def test_swift_udp_retrans_skip_missing_meta_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)

    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport
    session.send_meta.pop(2, None)
    original_attempts = dict(session.send_attempts)
    feedback = ControlPacket.build_full(0, 2, [2])
    session.confirm_with_feedback(feedback.last_in_order_rx, feedback.highest_rx, feedback.missed)
    with mock.patch.object(myudp, "now_ns", return_value=12_000_000_000):
        proto._schedule_retrans(feedback.missed)

    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "schedule_udp_retrans_due_to_control",
            "now_ns": 12_000_000_000,
            "missed": [2],
            "rtt_est_ms": session.proto.rtt_est_ms,
            "send_buffer": sorted(session.send_buf),
            "send_meta": _send_meta_payload(session),
            "send_tx_ns": _int_keyed_map(session.send_txns),
            "last_retx_ns": _int_keyed_map({}),
            "send_attempts": _int_keyed_map(original_attempts),
            "peer_reported_missing": sorted(session.peer_reported_missing),
            "last_send_ns": session.last_send_ns,
            "last_rx_tx_ns": 0,
            "last_rx_wall_ns": 0,
        },
    )
    assert len(transport.frames) == 2
    assert swift["emitted_counters"] == []
    assert swift["frames_hex"] == []
    assert swift["send_attempts"] == _int_keyed_map(original_attempts)


def test_swift_udp_reported_missing_sweep_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)
    session.send_application_payload(b"three", transport)

    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport
    session.proto.rtt_est_ms = 100.0

    session.confirm_with_feedback(last_in_order=0, highest=3, missed=[2])
    with mock.patch.object(myudp, "now_ns", return_value=session.send_txns[2] + 150_000_000):
        proto._schedule_retrans([2])

    attempts_after_schedule = dict(session.send_attempts)
    last_retx_after_schedule = dict(session.last_retx_ns)

    session.confirm_with_feedback(last_in_order=0, highest=3, missed=[])
    with mock.patch.object(myudp, "now_ns", return_value=session.last_retx_ns[2] + 110_000_000):
        proto._retx_sweep_reported_missing()

    python_frame = transport.frames[-1]
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "sweep_udp_reported_missing_retrans",
            "now_ns": last_retx_after_schedule[2] + 110_000_000,
            "rtt_est_ms": session.proto.rtt_est_ms,
            "send_buffer": sorted(session.send_buf),
            "send_meta": _send_meta_payload(session),
            "send_tx_ns": _int_keyed_map(session.send_txns),
            "last_retx_ns": _int_keyed_map(last_retx_after_schedule),
            "send_attempts": _int_keyed_map(attempts_after_schedule),
            "peer_reported_missing": [2],
            "peer_missed_count": 1,
            "last_send_ns": session.last_send_ns,
            "last_rx_tx_ns": 0,
            "last_rx_wall_ns": 0,
        },
    )
    assert swift["emitted_counters"] == [2]
    assert swift["frames_hex"] == [python_frame.hex()]
    assert swift["send_attempts"] == _int_keyed_map(dict(session.send_attempts))
    assert swift["peer_reported_missing"] == [2]


def test_swift_udp_unconfirmed_sweep_matches_python(swift_channelmux_runner: Path) -> None:
    session = Session(proto=Protocol(BaseFrameV2))
    transport = _FakeDatagramTransport()
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)

    proto = myudp.PeerProtocol(session, lambda: None, lambda _data: None, proto=session.proto)
    proto.send_port = transport
    session.proto.rtt_est_ms = 100.0
    sweep_now_ns = max(session.send_txns.values()) + 200_000_000
    with mock.patch.object(myudp, "now_ns", return_value=sweep_now_ns):
        proto._retx_sweep_unconfirmed()

    python_frames = [frame.hex() for frame in transport.frames[-2:]]
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "sweep_udp_unconfirmed_retrans",
            "now_ns": sweep_now_ns,
            "rtt_est_ms": session.proto.rtt_est_ms,
            "send_buffer": [1, 2],
            "send_meta": _send_meta_payload(session),
            "send_tx_ns": _int_keyed_map(session.send_txns),
            "last_retx_ns": _int_keyed_map({}),
            "send_attempts": _int_keyed_map({1: 1, 2: 1}),
            "peer_reported_missing": [],
            "peer_missed_count": 0,
            "last_send_ns": max(session.send_txns.values()),
            "last_rx_tx_ns": 0,
            "last_rx_wall_ns": 0,
        },
    )
    assert swift["emitted_counters"] == [1, 2]
    assert swift["frames_hex"] == python_frames
    assert swift["send_attempts"] == {"1": 2, "2": 2}
    assert swift["peer_reported_missing"] == []


@pytest.mark.parametrize("send_port_present", [True, False])
def test_swift_udp_inbound_control_matches_python(
    swift_channelmux_runner: Path,
    send_port_present: bool,
) -> None:
    python = _python_inbound_control_summary(
        send_port_present=send_port_present,
        packet_last_in_order=0,
        packet_highest=2,
        packet_missed=[2],
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "handle_udp_inbound_control",
            "now_ns": int(python["now_ns"]),
            "packet_last_in_order": 0,
            "packet_highest": 2,
            "packet_missed": [2],
            "send_port_present": send_port_present,
            "send_buffer": python["pre_send_buffer"],
            "peer_reported_missing": [],
            "send_meta": python["pre_send_meta"],
            "send_tx_ns": python["pre_send_tx_ns"],
            "last_retx_ns": {},
            "send_attempts": python["pre_send_attempts"],
            "last_send_ns": int(max(int(value) for value in python["pre_send_tx_ns"].values())),
            "last_rx_tx_ns": 0,
            "last_rx_wall_ns": 0,
            "receiver_expected": 1,
            "receiver_missing_count": 0,
            "last_sent_last_in_order": 0,
            "last_control_sent_ns": 0,
            "established_ns": 0,
            "rtt_est_ms": 100.0,
        },
    )
    assert swift["send_buffer"] == python["send_buffer"]
    assert swift["peer_reported_missing"] == python["peer_reported_missing"]
    assert swift["last_ack_peer"] == python["last_ack_peer"]
    assert swift["emitted_counters"] == python["emitted_counters"]
    assert swift["frames_hex"] == python["frames_hex"]
    assert swift["send_attempts"] == python["send_attempts"]
    assert swift["peer_missed_count"] == python["peer_missed_count"]
    assert swift["flush_requested"] == python["flush_requested"]
    assert swift["control_should_emit"] == python["control_should_emit"]
    assert swift["control_reason"] == python["control_reason"]


@pytest.mark.parametrize(
    "payload",
    [
        {"send_port_present": True, "tx_ns": 5_000, "echo_ns": 0, "now_ns": 6_000},
        {"send_port_present": False, "tx_ns": 5_000, "echo_ns": 0, "now_ns": 6_000},
        {"send_port_present": True, "tx_ns": 10_000, "echo_ns": 9_500, "now_ns": 10_500},
    ],
)
def test_swift_udp_inbound_idle_matches_python(
    swift_channelmux_runner: Path,
    payload: dict[str, object],
) -> None:
    python = _python_inbound_idle_summary(
        send_port_present=payload["send_port_present"],
        tx_ns=payload["tx_ns"],
        echo_ns=payload["echo_ns"],
        now_ns=payload["now_ns"],
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "handle_udp_inbound_idle",
            "now_ns": payload["now_ns"],
            "tx_ns": payload["tx_ns"],
            "echo_ns": payload["echo_ns"],
            "send_port_present": payload["send_port_present"],
            "established_ns": 0,
            "prior_rtt_est_ms": 0.0,
            "prior_transmit_delay_est_ms": 0.0,
        },
    )
    assert swift == python


@pytest.mark.parametrize(
    "payload",
    [
        {
            "pre_builder": [(2, FRAME_CONT, 3, b"def"), (3, FRAME_CONT, 6, b"ghi")],
            "frame_builder": (1, FRAME_FIRST, 9, b"abc"),
            "tx_ns": 2_000,
            "echo_ns": 0,
            "now_ns": 3_000,
            "send_port_present": True,
            "last_sent_last_in_order": 3,
            "last_control_sent_ns": 0,
            "established_ns": 0,
            "prior_rtt_est_ms": 0.0,
            "prior_transmit_delay_est_ms": 0.0,
        },
        {
            "pre_builder": [],
            "frame_builder": (2, FRAME_CONT, 3, b"def"),
            "tx_ns": 10_000,
            "echo_ns": 9_500,
            "now_ns": 10_500,
            "send_port_present": True,
            "last_sent_last_in_order": 0,
            "last_control_sent_ns": 0,
            "established_ns": 0,
            "prior_rtt_est_ms": 0.0,
            "prior_transmit_delay_est_ms": 7.0,
        },
    ],
)
def test_swift_udp_inbound_data_matches_python(
    swift_channelmux_runner: Path,
    payload: dict[str, object],
) -> None:
    with mock.patch.object(myudp, "now_ns", return_value=payload["tx_ns"]):
        pre_frames = [
            DataPacket.build_full(counter, frame_type, len_or_offset, data).raw
            for counter, frame_type, len_or_offset, data in payload["pre_builder"]
        ]
        frame_builder = payload["frame_builder"]
        frame = DataPacket.build_full(frame_builder[0], frame_builder[1], frame_builder[2], frame_builder[3]).raw
    python = _python_inbound_data_summary(
        pre_frames=pre_frames,
        frame=frame,
        tx_ns=payload["tx_ns"],
        echo_ns=payload["echo_ns"],
        now_ns=payload["now_ns"],
        send_port_present=payload["send_port_present"],
        last_sent_last_in_order=payload["last_sent_last_in_order"],
        last_control_sent_ns=payload["last_control_sent_ns"],
        established_ns=payload["established_ns"],
        prior_rtt_est_ms=payload["prior_rtt_est_ms"],
        prior_transmit_delay_est_ms=payload["prior_transmit_delay_est_ms"],
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "handle_udp_inbound_data",
            "pre_frames_hex": [item.hex() for item in pre_frames],
            "frame_hex": frame.hex(),
            "now_ns": payload["now_ns"],
            "tx_ns": payload["tx_ns"],
            "echo_ns": payload["echo_ns"],
            "send_port_present": payload["send_port_present"],
            "established_ns": payload["established_ns"],
            "last_sent_last_in_order": payload["last_sent_last_in_order"],
            "last_control_sent_ns": payload["last_control_sent_ns"],
            "prior_rtt_est_ms": payload["prior_rtt_est_ms"],
            "prior_transmit_delay_est_ms": payload["prior_transmit_delay_est_ms"],
        },
    )
    assert swift["snapshot"] == python


def test_swift_udp_peer_runtime_data_sequence_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    events = [
        {
            "frame_hex": DataPacket.build_full(2, FRAME_CONT, 3, b"def").raw.hex(),
            "tx_ns": 1_000,
            "echo_ns": 0,
            "now_ns": 1_500,
        },
        {
            "frame_hex": DataPacket.build_full(1, FRAME_FIRST, 6, b"abc").raw.hex(),
            "tx_ns": 10_000,
            "echo_ns": 9_500,
            "now_ns": 10_500,
        },
        {
            "frame_hex": DataPacket.build_full(4, FRAME_CONT, 3, b"def").raw.hex(),
            "tx_ns": 20_000,
            "echo_ns": 0,
            "now_ns": 20_250,
        },
        {
            "frame_hex": DataPacket.build_full(3, FRAME_FIRST, 6, b"abc").raw.hex(),
            "tx_ns": 30_000,
            "echo_ns": 0,
            "now_ns": 30_500,
        },
    ]
    python = _python_peer_runtime_data_sequence_summary(
        events=events,
        send_port_present=True,
        last_sent_last_in_order=0,
        last_control_sent_ns=0,
        established_ns=0,
        prior_rtt_est_ms=0.0,
        prior_transmit_delay_est_ms=7.0,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_data_sequence",
            "events": events,
            "send_port_present": True,
            "last_sent_last_in_order": 0,
            "last_control_sent_ns": 0,
            "established_ns": 0,
            "prior_rtt_est_ms": 0.0,
            "prior_transmit_delay_est_ms": 7.0,
        },
    )
    assert swift["snapshots"] == python


def test_swift_udp_peer_runtime_idle_sequence_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    events = [
        {
            "tx_ns": 10_000,
            "echo_ns": 9_000,
            "now_ns": 10_500,
        },
        {
            "tx_ns": 20_000,
            "echo_ns": 0,
            "now_ns": 20_250,
        },
    ]
    python = _python_peer_runtime_idle_sequence_summary(
        events=events,
        send_port_present=True,
        established_ns=0,
        prior_rtt_est_ms=0.0,
        prior_transmit_delay_est_ms=0.0,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_idle_sequence",
            "events": events,
            "send_port_present": True,
            "established_ns": 0,
            "prior_rtt_est_ms": 0.0,
            "prior_transmit_delay_est_ms": 0.0,
        },
    )
    assert swift["snapshots"] == python


def test_swift_udp_peer_runtime_control_sequence_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    transport = _FakeDatagramTransport()
    session = Session(proto=Protocol(BaseFrameV2))
    session.send_application_payload(b"one", transport)
    session.send_application_payload(b"two", transport)
    send_buffer = sorted(session.send_buf)
    send_meta = _send_meta_payload(session)
    send_tx_ns = _int_keyed_map(session.send_txns)
    send_attempts = _int_keyed_map(dict(session.send_attempts))
    last_send_ns = session.last_send_ns

    events = [
        {
            "now_ns": max(session.send_txns.values()) + 150_000_000,
            "packet_last_in_order": 1,
            "packet_highest": 2,
            "packet_missed": [2],
        },
        {
            "now_ns": max(session.send_txns.values()) + 300_000_000,
            "packet_last_in_order": 2,
            "packet_highest": 2,
            "packet_missed": [],
        },
    ]
    python = _python_peer_runtime_control_sequence_summary(
        events=events,
        send_port_present=True,
        established_ns=0,
        last_sent_last_in_order=0,
        last_control_sent_ns=0,
        prior_rtt_est_ms=100.0,
        prior_transmit_delay_est_ms=0.0,
    )["snapshots"]
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_control_sequence",
            "events": events,
            "send_port_present": True,
            "established_ns": 0,
            "last_sent_last_in_order": 0,
            "last_control_sent_ns": 0,
            "prior_rtt_est_ms": 100.0,
            "prior_transmit_delay_est_ms": 0.0,
            "send_buffer": send_buffer,
            "send_meta": send_meta,
            "send_tx_ns": send_tx_ns,
            "last_retx_ns": {},
            "send_attempts": send_attempts,
            "peer_reported_missing": [],
            "last_ack_peer": 0,
            "peer_missed_count": 0,
            "last_send_ns": last_send_ns,
        },
    )
    for item in python:
        item.pop("flush_count")
    assert swift["snapshots"] == python


def test_swift_udp_peer_runtime_control_timer_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    pre_frames = [DataPacket.build_full(1, FRAME_FIRST, 3, b"abc").raw]
    python = _python_peer_runtime_control_timer_summary(
        pre_frames=pre_frames,
        send_port_present=True,
        now_ns=60_000_000,
        established_ns=1,
        last_sent_last_in_order=0,
        last_control_sent_ns=0,
        prior_rtt_est_ms=100.0,
        prior_transmit_delay_est_ms=0.0,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_control_timer",
            "pre_frames_hex": [frame.hex() for frame in pre_frames],
            "send_port_present": True,
            "now_ns": 60_000_000,
            "established_ns": 1,
            "last_sent_last_in_order": 0,
            "last_control_sent_ns": 0,
            "prior_rtt_est_ms": 100.0,
            "prior_transmit_delay_est_ms": 0.0,
        },
    )
    assert swift["snapshot"] == python


def test_swift_udp_peer_runtime_retransmit_timer_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    seed = _python_peer_runtime_retransmit_timer_summary(
        now_ns=0,
        send_port_present=True,
        prior_rtt_est_ms=100.0,
    )
    python = _python_peer_runtime_retransmit_timer_summary(
        now_ns=max(int(value) for value in seed["send_tx_ns"].values()) + 200_000_000,
        send_port_present=True,
        prior_rtt_est_ms=100.0,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_retransmit_timer",
            "send_port_present": True,
            "now_ns": max(int(value) for value in python["last_retx_ns"].values()) if python["last_retx_ns"] else max(int(value) for value in seed["send_tx_ns"].values()) + 200_000_000,
            "prior_rtt_est_ms": 100.0,
            "prior_transmit_delay_est_ms": 0.0,
            "send_buffer": seed["send_buffer"],
            "send_meta": seed["send_meta"],
            "send_tx_ns": seed["send_tx_ns"],
            "last_retx_ns": seed["last_retx_ns_seed"],
            "send_attempts": {str(key): value for key, value in {1: 1, 2: 1}.items()},
            "peer_reported_missing": [1],
            "last_ack_peer": seed["last_ack_peer"],
            "peer_missed_count": 0,
            "last_send_ns": max(int(value) for value in seed["send_tx_ns"].values()),
        },
    )
    for key in ("send_buffer", "send_meta", "send_tx_ns", "last_retx_ns_seed", "last_ack_peer"):
        python.pop(key)
    assert swift["snapshot"] == python


def test_swift_udp_peer_runtime_send_payload_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    payload = bytes(range(64))
    python = _python_peer_runtime_send_payload_summary(
        payload=payload,
        now_ns=12_345_678,
        echo_ns=0,
        next_counter=7,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_send_payload",
            "payload_hex": payload.hex(),
            "now_ns": 12_345_678,
            "echo_ns": 0,
            "next_counter": 7,
        },
    )
    assert swift["snapshot"] == python


def test_swift_udp_peer_runtime_build_control_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    pre_frames = [
        DataPacket.build_full(1, FRAME_FIRST, 3, b"abc").raw,
        DataPacket.build_full(3, FRAME_CONT, 3, b"ghi").raw,
    ]
    python = _python_peer_runtime_build_control_summary(
        pre_frames=pre_frames,
        now_ns=55_000,
        echo_ns=0,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_udp_peer_runtime_build_control",
            "pre_frames_hex": [frame.hex() for frame in pre_frames],
            "now_ns": 55_000,
            "echo_ns": 0,
        },
    )
    assert swift["snapshot"] == python


def test_swift_channelmux_local_tun_packet_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_local_tun_packet_summary()
    swift = _run_swift(
        swift_channelmux_runner,
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


def test_swift_channelmux_inbound_tun_data_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_inbound_tun_data_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_inbound_tun_data",
            "chan_id": 7,
            "body_hex": "616263",
            "mtu": 1500,
            "bound_chan_id": 7,
        },
    )
    assert swift["snapshot"] == python


def test_swift_channelmux_tun_open_then_local_packet_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tun_open_then_local_packet_summary()
    swift = _run_swift(
        swift_channelmux_runner,
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


def test_swift_channelmux_local_tun_chunked_open_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_local_tun_chunked_open_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_local_tun_packet",
            "packet_hex": "616263",
            "mtu": 1600,
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tun_id": 1,
            "session_max_app_payload": 96,
            "spec": python["spec"],
        },
    )
    python.pop("spec")
    assert swift["snapshot"] == python


def test_swift_channelmux_local_tun_throttle_sequence_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_local_tun_throttle_sequence_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_local_tun_packet_sequence",
            "packets_hex": [
                (b"a" * 100).hex(),
                (b"b" * 80).hex(),
                (b"c" * 20).hex(),
            ],
            "mtu": 1500,
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tun_id": 1,
            "buffered_frames_sequence": [0, 1, 1],
            "now_ns_sequence": [0, 100_000_000, 100_000_000],
            "spec": python["spec"],
        },
    )
    python.pop("spec")
    assert swift["snapshots"] == python["snapshots"]


def test_swift_channelmux_inbound_tun_fragment_sequence_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_inbound_tun_fragment_sequence_summary()
    swift = _run_swift(
        swift_channelmux_runner,
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


def test_swift_channelmux_tun_close_then_local_packet_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tun_close_then_local_packet_summary()
    swift = _run_swift(
        swift_channelmux_runner,
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


def test_swift_channelmux_local_udp_server_datagram_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_local_udp_server_datagram_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_local_udp_server_datagram",
            "payload_hex": "616263",
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_udp_id": 1,
            "spec": python["spec"],
            "service_key": python["service_key"],
            "addr_host": python["addr_host"],
            "addr_port": python["addr_port"],
        },
    )
    python.pop("spec")
    python.pop("service_key")
    python.pop("addr_host")
    python.pop("addr_port")
    assert swift["snapshot"] == python


def test_swift_channelmux_local_udp_server_fragmented_datagram_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_local_udp_server_fragmented_datagram_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_local_udp_server_datagram",
            "payload_hex": bytes(index % 251 for index in range(180)).hex(),
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_udp_id": 1,
            "session_max_app_payload": 96,
            "spec": python["spec"],
            "service_key": python["service_key"],
            "addr_host": python["addr_host"],
            "addr_port": python["addr_port"],
        },
    )
    python.pop("spec")
    python.pop("service_key")
    python.pop("addr_host")
    python.pop("addr_port")
    assert swift["snapshot"] == python


def test_swift_channelmux_udp_server_open_then_inbound_data_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_server_open_then_inbound_data_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_server_open_then_inbound_data",
            "payload_hex": "616263",
            "inbound_hex": "7265706c79",
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "spec": python["spec"],
            "service_key": python["service_key"],
            "addr_host": python["addr_host"],
            "addr_port": python["addr_port"],
        },
    )
    python.pop("spec")
    python.pop("service_key")
    python.pop("addr_host")
    python.pop("addr_port")
    assert swift == python


def test_swift_channelmux_udp_server_open_then_inbound_fragment_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_server_open_then_inbound_fragment_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_server_open_then_inbound_fragment_sequence",
            "payload_hex": "616263",
            "fragments_hex": python["fragments_hex"],
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "spec": python["spec"],
            "service_key": python["service_key"],
            "addr_host": python["addr_host"],
            "addr_port": python["addr_port"],
        },
    )
    python.pop("spec")
    python.pop("service_key")
    python.pop("addr_host")
    python.pop("addr_port")
    python.pop("fragments_hex")
    assert swift == python


def test_swift_channelmux_udp_server_close_then_local_datagram_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_server_close_then_local_datagram_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_server_close_then_local_datagram",
            "payload_hex": "616263",
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "spec": python["spec"],
            "service_key": python["service_key"],
            "addr_host": python["addr_host"],
            "addr_port": python["addr_port"],
        },
    )
    python.pop("spec")
    python.pop("service_key")
    python.pop("addr_host")
    python.pop("addr_port")
    assert swift == python


def test_swift_channelmux_udp_client_open_then_connect_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_client_open_then_connect_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_client_open_then_connect",
            "chan_id": 41,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "local_addr_host": "0.0.0.0",
            "local_addr_port": 41041,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 5353,
        },
    )
    python.pop("open_payload_hex")
    assert swift == python


def test_swift_channelmux_udp_client_buffer_connect_then_data_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_client_buffer_connect_then_data_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_client_open_buffer_connect_then_data",
            "chan_id": 41,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "buffered_hex": python["buffered_hex"],
            "immediate_hex": python["immediate_hex"],
            "local_addr_host": "0.0.0.0",
            "local_addr_port": 41041,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 5353,
        },
    )
    python.pop("open_payload_hex")
    python.pop("buffered_hex")
    python.pop("immediate_hex")
    assert swift == python


def test_swift_channelmux_udp_client_open_connect_then_local_datagram_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_client_open_connect_then_local_datagram_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_client_open_connect_then_local_datagram",
            "chan_id": 41,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "payload_hex": python["payload_hex"],
            "session_max_app_payload": 96,
            "local_addr_host": "0.0.0.0",
            "local_addr_port": 41041,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 5353,
        },
    )
    python.pop("open_payload_hex")
    python.pop("payload_hex")
    assert swift == python


def test_swift_channelmux_udp_client_open_connect_then_inbound_fragment_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_client_open_connect_then_inbound_fragment_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_client_open_connect_then_inbound_fragment_sequence",
            "chan_id": 41,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "fragments_hex": python["fragments_hex"],
            "local_addr_host": "0.0.0.0",
            "local_addr_port": 41041,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 5353,
        },
    )
    python.pop("open_payload_hex")
    python.pop("fragments_hex")
    assert swift == python


def test_swift_channelmux_udp_client_open_buffer_then_close_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_udp_client_open_buffer_then_close_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_udp_client_open_buffer_then_close",
            "chan_id": 41,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "buffered_hex": python["buffered_hex"],
        },
    )
    python.pop("open_payload_hex")
    python.pop("buffered_hex")
    assert swift == python


def test_swift_channelmux_tcp_client_open_then_connect_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_client_open_then_connect_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_client_open_then_connect",
            "chan_id": 51,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "local_addr_host": "127.0.0.1",
            "local_addr_port": 51051,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 8080,
        },
    )
    python.pop("open_payload_hex")
    assert swift == python


def test_swift_channelmux_tcp_client_buffer_connect_then_data_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_client_buffer_connect_then_data_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_client_open_buffer_connect_then_data",
            "chan_id": 51,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "buffered_hex": python["buffered_hex"],
            "immediate_hex": python["immediate_hex"],
            "local_addr_host": "127.0.0.1",
            "local_addr_port": 51051,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 8080,
        },
    )
    python.pop("open_payload_hex")
    python.pop("buffered_hex")
    python.pop("immediate_hex")
    assert swift == python


def test_swift_channelmux_tcp_client_open_connect_then_local_data_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_client_open_connect_then_local_data_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_client_open_connect_then_local_data",
            "chan_id": 51,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "payload_hex": python["payload_hex"],
            "overlay_connected": True,
            "session_max_app_payload": 96,
            "local_addr_host": "127.0.0.1",
            "local_addr_port": 51051,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 8080,
        },
    )
    python.pop("open_payload_hex")
    python.pop("payload_hex")
    assert swift == python


def test_swift_channelmux_tcp_client_open_buffer_then_close_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_client_open_buffer_then_close_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_client_open_buffer_then_close",
            "chan_id": 51,
            "peer_id": 0,
            "open_payload_hex": python["open_payload_hex"],
            "buffered_hex": python["buffered_hex"],
        },
    )
    python.pop("open_payload_hex")
    python.pop("buffered_hex")
    assert swift == python


def test_swift_channelmux_tcp_client_open_then_local_eof_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_client_open_then_local_eof_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_client_open_then_local_eof",
            "chan_id": 51,
            "open_payload_hex": python["open_payload_hex"],
            "peer_id": 0,
            "overlay_connected": True,
            "local_addr_host": "127.0.0.1",
            "local_addr_port": 51051,
            "peer_addr_host": "127.0.0.1",
            "peer_addr_port": 8080,
        },
    )
    python.pop("open_payload_hex")
    assert swift == python


def test_swift_channelmux_tcp_server_accept_then_local_data_then_eof_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_server_accept_then_local_data_then_eof_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_server_accept_then_local_data_then_eof",
            "payload_hex": "".join(f"{index % 251:02x}" for index in range(64)),
            "overlay_connected": True,
            "accepting_enabled": True,
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tcp_id": 1,
            "session_max_app_payload": 96,
            "spec": python["spec"],
        },
    )
    python.pop("spec")
    assert swift == python


def test_swift_channelmux_tcp_server_accept_then_inbound_data_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_server_accept_then_inbound_data_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_server_accept_then_inbound_data",
            "inbound_hex": "7265706c79",
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tcp_id": 1,
            "spec": python["spec"],
        },
    )
    python.pop("spec")
    assert swift == python


def test_swift_channelmux_tcp_server_accept_then_inbound_close_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_channelmux_tcp_server_accept_then_inbound_close_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_channelmux_tcp_server_accept_then_inbound_close",
            "instance_id": 0x1122334455667788,
            "connection_seq": 0x10203040,
            "next_tcp_id": 1,
            "spec": python["spec"],
        },
    )
    python.pop("spec")
    assert swift == python


def test_swift_control_chunk_reassembly_matches_python(swift_channelmux_runner: Path) -> None:
    mux = _make_mux(connected=True, max_app_payload_size=96)
    try:
        payload = bytes(index % 197 for index in range(255))
        mux._ctrl_chunk_next_txid = 12
        mux._send_chunked_control_payload(
            chan_id=23,
            proto=ChannelMux.Proto.TCP,
            chunk_mtype=ChannelMux.MType.OPEN_CHUNK,
            payload=payload,
        )
        frames = [
            bytes(parsed[4]).hex()
            for wire in mux.session.sent
            for parsed in [mux._unpack_mux(wire)]
            if parsed is not None and parsed[3] == ChannelMux.MType.OPEN_CHUNK
        ]
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "reassemble_control_chunks",
                "chan_id": 23,
                "peer_id": 5,
                "proto": "tcp",
                "mtype": "open_chunk",
                "chunks_hex": frames,
            },
        )
        assert swift["assembled_hex"] == payload.hex()
    finally:
        _close_mux(mux)


def test_python_reassembles_swift_control_chunks(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        payload = bytes(index % 211 for index in range(300))
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "chunk_control_payload",
                "txid": 27,
                "max_app_payload": 96,
                "payload_hex": payload.hex(),
            },
        )
        assembled = None
        for frame_hex in swift["frames_hex"]:
            assembled = mux._consume_control_chunk(
                chan_id=0,
                proto=ChannelMux.Proto.UDP,
                mtype=ChannelMux.MType.REMOTE_SERVICES_SET_V2_CHUNK,
                payload=bytes.fromhex(frame_hex),
                peer_id=19,
            ) or assembled
        assert assembled == payload
    finally:
        _close_mux(mux)


def test_swift_open_payload_exact_bytes_without_metadata(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        spec = ChannelMux.ServiceSpec(
            svc_id=9,
            l_proto="tcp",
            l_bind="0.0.0.0",
            l_port=18080,
            r_proto="tcp",
            r_host="127.0.0.1",
            r_port=8080,
        )
        python_payload = mux._build_open_v4(spec)
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "build_open",
                "instance_id": mux._mux_instance_id,
                "connection_seq": mux._mux_connection_seq,
                "spec": _service_spec_payload(spec),
            },
        )
        assert swift["hex"] == python_payload.hex()
    finally:
        _close_mux(mux)


def test_swift_open_payload_roundtrip_matches_python_with_metadata(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        spec = ChannelMux.ServiceSpec(
            svc_id=7,
            l_proto="tcp",
            l_bind="0.0.0.0",
            l_port=18080,
            r_proto="tcp",
            r_host="127.0.0.1",
            r_port=8080,
            name="web-service",
            lifecycle_hooks={"client": {"on_connected": {"argv": ["echo", "ok"]}}},
            options={"note": "metadata", "enabled": True},
        )
        python_payload = mux._build_open_v4(spec)
        python_parsed = mux._parse_open_with_meta(python_payload)
        assert python_parsed is not None
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "parse_open",
                "payload_hex": python_payload.hex(),
            },
        )
        assert swift["open"] == _python_open_payload(python_parsed)
    finally:
        _close_mux(mux)


def test_swift_remote_services_exact_bytes_without_metadata(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        services = [
            ChannelMux.ServiceSpec(1, "udp", "127.0.0.1", 10001, "udp", "127.0.0.1", 20001),
            ChannelMux.ServiceSpec(2, "tcp", "127.0.0.1", 10002, "tcp", "127.0.0.1", 20002),
            ChannelMux.ServiceSpec(3, "tun", "obtun0", 1500, "tun", "obtun1", 1500),
        ]
        python_payload = mux._encode_remote_services_set_v2(services)
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "encode_remote_services",
                "instance_id": mux._mux_instance_id,
                "connection_seq": mux._mux_connection_seq,
                "services": [_service_spec_payload(spec) for spec in services],
            },
        )
        assert swift["hex"] == python_payload.hex()
    finally:
        _close_mux(mux)


def test_swift_remote_services_roundtrip_matches_python_with_metadata(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
        services = [
            ChannelMux.ServiceSpec(
                svc_id=3,
                l_proto="udp",
                l_bind="0.0.0.0",
                l_port=16667,
                r_proto="udp",
                r_host="127.0.0.1",
                r_port=16666,
                name="udp-publish",
                lifecycle_hooks={"listener": {"on_created": {"argv": ["echo", "created"]}}},
                options={"tag": "alpha", "priority": 4},
            )
        ]
        python_payload = mux._encode_remote_services_set_v2(services)
        python_decoded = mux._decode_remote_services_set_v2(python_payload)
        assert python_decoded is not None
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "decode_remote_services",
                "payload_hex": python_payload.hex(),
            },
        )
        assert swift["remote_services"] == {
            "instance_id": str(python_decoded[0]),
            "connection_seq": python_decoded[1],
            "services": [_service_spec_payload(spec) for spec in python_decoded[2]],
        }
    finally:
        _close_mux(mux)


def test_swift_shared_tun_ownership_metadata_roundtrip_matches_python(swift_channelmux_runner: Path) -> None:
    mux = _make_mux()
    try:
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
                        {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"], "ipv6": ["fd20:107::2"]},
                        {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                    ],
                }
            },
        )
        python_payload = mux._encode_remote_services_set_v2([spec])
        python_decoded = mux._decode_remote_services_set_v2(python_payload)
        assert python_decoded is not None
        swift = _run_swift(
            swift_channelmux_runner,
            {
                "action": "decode_remote_services",
                "payload_hex": python_payload.hex(),
            },
        )
        assert swift["remote_services"] == {
            "instance_id": str(python_decoded[0]),
            "connection_seq": python_decoded[1],
            "services": [_service_spec_payload(spec) for spec in python_decoded[2]],
        }
    finally:
        _close_mux(mux)


def test_swift_securelink_frame_exact_bytes(swift_channelmux_runner: Path) -> None:
    from obstacle_bridge.bridge import SecureLinkPskSession

    payload = b"secure-frame"
    python_frame = SecureLinkPskSession._build_frame(4, 0x1122334455667788, 9, payload, flags=3)
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "build_securelink_frame",
            "sl_type": 4,
            "session_id": 0x1122334455667788,
            "counter": 9,
            "flags": 3,
            "payload_hex": payload.hex(),
        },
    )
    assert swift["hex"] == python_frame.hex()


def test_swift_securelink_frame_roundtrip_matches_python(swift_channelmux_runner: Path) -> None:
    from obstacle_bridge.bridge import SecureLinkPskSession

    python_frame = SecureLinkPskSession._build_frame(1, 5001, 0, bytes.fromhex("aa55"))
    python_parsed = SecureLinkPskSession._parse_frame(python_frame)
    assert python_parsed is not None
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "parse_securelink_frame",
            "frame_hex": python_frame.hex(),
        },
    )
    assert swift["frame"] == {
        "sl_type": python_parsed[0],
        "session_id": str(python_parsed[1]),
        "counter": str(python_parsed[2]),
        "payload_hex": python_parsed[3].hex(),
    }


def test_swift_securelink_nonce_parity(swift_channelmux_runner: Path) -> None:
    from obstacle_bridge.bridge import SecureLinkPskSession

    python_nonce = SecureLinkPskSession._nonce(0x0102030405060708)
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "securelink_nonce",
            "counter": 0x0102030405060708,
        },
    )
    assert swift["hex"] == python_nonce.hex()


def test_swift_securelink_derive_keys_parity(swift_channelmux_runner: Path) -> None:
    securelink = _make_securelink_session("lab-secret")
    client_nonce = bytes(range(32))
    server_nonce = bytes(range(32, 64))
    python_c2s, python_s2c = securelink._derive_keys(5001, client_nonce, server_nonce)
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "derive_securelink_keys",
            "psk": "lab-secret",
            "session_id": 5001,
            "client_nonce_hex": client_nonce.hex(),
            "server_nonce_hex": server_nonce.hex(),
        },
    )
    assert swift["c2s_hex"] == python_c2s.hex()
    assert swift["s2c_hex"] == python_s2c.hex()


def test_swift_securelink_json_payload_exact_bytes(swift_channelmux_runner: Path) -> None:
    from obstacle_bridge.bridge import SecureLinkPskSession

    obj = {
        "capabilities": [1, 2],
        "name": "secure-node",
        "meta": {"enabled": True, "count": 3},
    }
    python_payload = SecureLinkPskSession._json_payload(obj)
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "build_securelink_json",
            "object": obj,
        },
    )
    assert swift["hex"] == python_payload.hex()


def test_swift_securelink_json_roundtrip_matches_python(swift_channelmux_runner: Path) -> None:
    from obstacle_bridge.bridge import SecureLinkPskSession

    payload = SecureLinkPskSession._json_payload(
        {"role": "client", "limits": {"frames": 1, "seconds": 0}, "valid": True}
    )
    python_parsed = SecureLinkPskSession._parse_json_payload(payload)
    assert python_parsed is not None
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "parse_securelink_json",
            "payload_hex": payload.hex(),
        },
    )
    assert swift["object"] == python_parsed


def test_swift_compress_roundtrip_profitable_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_compress_roundtrip_profitable_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_compress_roundtrip_profitable",
            "payload_hex": _compress_pack_mux(0x00, b"A" * 512).hex(),
            "peer_id": 11,
            "max_app_payload": 4096,
            "min_bytes": 1,
            "transport": "tcp",
        },
    )
    assert swift == python


def test_swift_compress_client_peer_snapshot_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_compress_client_peer_snapshot_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_compress_client_peer_snapshot",
            "transport": "tcp",
            "configured_enabled": True,
            "is_peer_client": True,
            "peer_id": 0,
        },
    )
    assert swift == python


def test_swift_compress_send_no_gain_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_compress_send_no_gain_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_compress_send_no_gain",
            "payload_hex": _compress_pack_mux(0x00, bytes(range(256))).hex(),
            "max_app_payload": 4096,
            "min_bytes": 1,
            "transport": "tcp",
        },
    )
    assert swift == python


def test_swift_compress_invalid_rx_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_compress_invalid_rx_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_compress_invalid_rx",
            "payload_hex": _compress_pack_mux(0x80, b"not-zlib").hex(),
            "peer_id": 2,
            "transport": "tcp",
        },
    )
    assert swift == python


def test_swift_compress_oversize_rx_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_compress_oversize_rx_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_compress_oversize_rx",
            "payload_hex": _compress_pack_mux(0x80, zlib.compress(b"B" * 500, 3)).hex(),
            "peer_id": 3,
            "transport": "tcp",
            "max_app_payload": 80,
        },
    )
    assert swift == python


def test_swift_compress_server_activation_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_compress_server_activation_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_compress_server_activation",
            "payload_hex": _compress_pack_mux(0x00, b"C" * 512).hex(),
            "compressed_in_hex": _compress_pack_mux(0x80, zlib.compress(b"D" * 512, 9)).hex(),
            "peer_id": 44,
            "transport": "tcp",
            "configured_enabled": False,
            "is_peer_client": False,
            "level": 1,
            "min_bytes": 4096,
            "allowed_mtypes": "data",
        },
    )
    assert swift == python


def test_swift_overlay_parse_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_overlay_parse_summary("myudp, tcp,quic,ws")
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_overlay_parse",
            "overlay_transport": "myudp, tcp,quic,ws",
            "has_configured_peer_by_transport": {},
        },
    )
    assert swift == python


def test_swift_overlay_parse_rejects_multi_transport_client_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_overlay_parse_summary("myudp,ws", udp_peer="127.0.0.1")
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_overlay_parse",
            "overlay_transport": "myudp,ws",
            "has_configured_peer_by_transport": {"myudp": True},
        },
    )
    assert swift == python


def test_swift_overlay_stack_default_compress_client_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_overlay_stack_plan_summary(transport="tcp", tcp_peer="127.0.0.1")
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_overlay_stack_plan",
            "transport": "tcp",
            "peer_host": "127.0.0.1",
            "secure_link_enabled": False,
            "secure_link_mode": "off",
            "secure_link_psk": "",
            "compress_layer_enabled": True,
            "compress_layer_algo": "zlib",
        },
    )
    assert swift == python


def test_swift_overlay_stack_passive_listener_compress_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_overlay_stack_plan_summary(transport="tcp", tcp_peer=None, compress_layer=False)
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_overlay_stack_plan",
            "transport": "tcp",
            "peer_host": None,
            "secure_link_enabled": False,
            "secure_link_mode": "off",
            "secure_link_psk": "",
            "compress_layer_enabled": False,
            "compress_layer_algo": "zlib",
        },
    )
    assert swift == python


def test_swift_overlay_stack_compress_above_secure_link_matches_python(
    swift_channelmux_runner: Path,
) -> None:
    python = _python_overlay_stack_plan_summary(
        transport="tcp",
        tcp_peer="127.0.0.1",
        secure_link=True,
        secure_link_mode="psk",
        secure_link_psk="lab-secret",
        compress_layer=True,
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_overlay_stack_plan",
            "transport": "tcp",
            "peer_host": "127.0.0.1",
            "secure_link_enabled": True,
            "secure_link_mode": "psk",
            "secure_link_psk": "lab-secret",
            "compress_layer_enabled": True,
            "compress_layer_algo": "zlib",
        },
    )
    assert swift == python


def test_swift_ws_binary_payload_codec_matches_python(swift_channelmux_runner: Path) -> None:
    wire = b"\x00hello"
    python = _python_ws_payload_codec_summary("binary", wire=wire)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_payload_codec", "mode": "binary", "wire_hex": wire.hex()},
    )
    assert swift == python


def test_swift_ws_base64_payload_codec_matches_python(swift_channelmux_runner: Path) -> None:
    wire = b"\x01hello\x00world"
    python = _python_ws_payload_codec_summary("base64", wire=wire)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_payload_codec", "mode": "base64", "wire_hex": wire.hex()},
    )
    assert swift == python


def test_swift_ws_json_base64_payload_codec_matches_python(swift_channelmux_runner: Path) -> None:
    wire = b"\x02pong"
    python = _python_ws_payload_codec_summary("json-base64", wire=wire)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_payload_codec", "mode": "json-base64", "wire_hex": wire.hex()},
    )
    assert swift == python


def test_swift_ws_semi_text_shape_payload_codec_matches_python(swift_channelmux_runner: Path) -> None:
    wire = b"abcdefghijkl"
    python = _python_ws_payload_codec_summary("semi-text-shape", wire=wire)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_payload_codec", "mode": "semi-text-shape", "wire_hex": wire.hex()},
    )
    assert swift == python


def test_swift_ws_invalid_json_payload_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_payload_codec_summary("json-base64", decode_message="not json")
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_payload_codec", "mode": "json-base64", "decode_text": "not json"},
    )
    assert swift == python


def test_swift_ws_invalid_semi_text_payload_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_payload_codec_summary("semi-text-shape", decode_message="not_valid!")
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_payload_codec", "mode": "semi-text-shape", "decode_text": "not_valid!"},
    )
    assert swift == python


def test_swift_ws_runtime_tx_success_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_tx_summary(timeout=False)
    swift = _run_swift(swift_channelmux_runner, {"action": "drive_ws_runtime_tx", "timeout": False})
    assert swift == python


def test_swift_ws_runtime_tx_timeout_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_tx_summary(timeout=True)
    swift = _run_swift(swift_channelmux_runner, {"action": "drive_ws_runtime_tx", "timeout": True})
    assert swift == python


def test_swift_ws_runtime_control_frames_match_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_control_frame_summary()
    swift = _run_swift(swift_channelmux_runner, {"action": "drive_ws_runtime_control_frames"})
    assert swift == python


def test_swift_ws_runtime_socket_config_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_socket_config_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_ws_runtime_socket_config",
            "tcp_user_timeout_available": python["tcp_user_timeout_ms"] is not None,
        },
    )
    assert swift == python


def test_swift_ws_runtime_disconnect_immediate_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_disconnect_summary(grace=0.0, reconnect=False)
    swift = _run_swift(swift_channelmux_runner, {"action": "drive_ws_runtime_disconnect", "grace": 0.0, "reconnect": False})
    assert swift == python


def test_swift_ws_runtime_disconnect_reconnect_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_disconnect_summary(grace=0.05, reconnect=True)
    swift = _run_swift(swift_channelmux_runner, {"action": "drive_ws_runtime_disconnect", "grace": 0.05, "reconnect": True})
    assert swift == python


def test_swift_ws_runtime_http_preflight_ok_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_http_preflight_summary(
        status_line=b"HTTP/1.1 200 OK\r\n",
        headers=[b"Content-Length: 13\r\n", b"Content-Type: text/html\r\n"],
        body=b"<html></html>",
        host_header="example.test",
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_ws_runtime_http_preflight",
            "status_line": "HTTP/1.1 200 OK",
            "headers": {"content-length": "13", "content-type": "text/html"},
            "body_hex": b"<html></html>".hex(),
            "host_header": "example.test",
        },
    )
    assert swift == python


def test_swift_ws_runtime_http_preflight_404_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_http_preflight_summary(
        status_line=b"HTTP/1.1 404 Not Found\r\n",
        headers=[],
        body=b"",
        host_header="127.0.0.1",
    )
    swift = _run_swift(
        swift_channelmux_runner,
        {
            "action": "drive_ws_runtime_http_preflight",
            "status_line": "HTTP/1.1 404 Not Found",
            "headers": {},
            "body_hex": "",
            "host_header": "127.0.0.1",
        },
    )
    assert swift == python


def test_swift_ws_runtime_connect_plan_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_connect_plan_summary(mode="semi-text-shape", proxy_active=False)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_runtime_connect_plan", "mode": "semi-text-shape", "proxy_active": False},
    )
    assert swift == python


def test_swift_ws_runtime_proxy_connect_plan_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_connect_plan_summary(mode="binary", proxy_active=True)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_runtime_connect_plan", "mode": "binary", "proxy_active": True},
    )
    assert swift == python


def test_swift_ws_runtime_listener_peer_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_listener_peer_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_runtime_listener_peer"},
    )
    assert swift == python


def test_swift_ws_runtime_proxy_helpers_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_ws_runtime_proxy_helpers_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_ws_runtime_proxy_helpers"},
    )
    assert swift == python


def test_swift_tcp_runtime_tx_immediate_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_tx_summary(writer_present=True)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_tx", "writer_present": True},
    )
    assert swift == python


def test_swift_tcp_runtime_tx_buffered_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_tx_summary(writer_present=False)
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_tx", "writer_present": False},
    )
    assert swift == python


def test_swift_tcp_runtime_connect_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_connect_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_connect"},
    )
    assert swift == python


def test_swift_tcp_runtime_socket_config_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_socket_config_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_socket_config"},
    )
    assert swift == python


def test_swift_tcp_runtime_reconnect_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_reconnect_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_reconnect"},
    )
    assert swift == python


def test_swift_tcp_runtime_server_accept_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_server_accept_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_server_accept"},
    )
    assert swift == python


def test_swift_tcp_runtime_server_close_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_server_close_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_server_close"},
    )
    assert swift == python


def test_swift_tcp_runtime_backpressure_matches_python(swift_channelmux_runner: Path) -> None:
    python = _python_tcp_runtime_backpressure_summary()
    swift = _run_swift(
        swift_channelmux_runner,
        {"action": "drive_tcp_runtime_backpressure"},
    )
    assert swift == python
