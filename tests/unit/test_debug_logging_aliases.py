import argparse
import asyncio
import logging
import socket
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from obstacle_bridge.bridge import AdminWebUI, ConfigAwareCLI, DebugLoggingConfigurator, SecureLinkPskSession
from obstacle_bridge.bridge_logging_ipc import NonBlockingUdpLogHandler, UdpLogQueryClient, UdpLogReceiver


def test_log_ws_session_applies_to_websockets_library_loggers():
    debug_cfg = DebugLoggingConfigurator(level_name="WARNING", console_level_name="CRITICAL")
    debug_cfg.apply()

    cfg = ConfigAwareCLI(description="test")
    args = argparse.Namespace(log_ws_session="CRITICAL")
    cfg._apply_per_section_overrides(args)

    assert logging.getLogger("ws_session").level == logging.CRITICAL
    assert logging.getLogger("websockets").level == logging.CRITICAL
    assert logging.getLogger("websockets.client").level == logging.CRITICAL
    assert logging.getLogger("websockets.server").level == logging.CRITICAL


def test_secure_link_logger_defaults_to_warning_until_overridden():
    debug_cfg = DebugLoggingConfigurator(level_name="WARNING", console_level_name="INFO")
    debug_cfg.apply()
    logging.getLogger("secure_link").setLevel(logging.NOTSET)

    inner = argparse.Namespace()
    args = argparse.Namespace(
        tcp_peer="127.0.0.1",
        secure_link_psk="lab-secret",
        secure_link_rekey_after_frames=0,
        secure_link_rekey_after_seconds=0.0,
        secure_link_retry_backoff_initial_ms=1000,
        secure_link_retry_backoff_max_ms=5000,
    )
    SecureLinkPskSession(inner, args, "tcp")

    assert logging.getLogger("secure_link").level == logging.WARNING


def test_log_secure_link_override_can_raise_verbosity():
    debug_cfg = DebugLoggingConfigurator(level_name="WARNING", console_level_name="INFO")
    debug_cfg.apply()

    cfg = ConfigAwareCLI(description="test")
    args = argparse.Namespace(log_secure_link="INFO")
    cfg._apply_per_section_overrides(args)

    assert logging.getLogger("secure_link").level == logging.INFO


def test_log_file_moves_previous_session_to_lastsession_on_start():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "bridge.log"
        lastsession_path = Path(tmpdir) / "bridge.log.lastsession"
        log_path.write_text("old-line\n", encoding="utf-8")
        lastsession_path.write_text("older-line\n", encoding="utf-8")

        debug_cfg = DebugLoggingConfigurator(
            level_name="INFO",
            console_level_name="CRITICAL",
            file_level_name="INFO",
            file_path=str(log_path),
            truncate_on_start=True,
        )
        debug_cfg.apply()
        logging.getLogger("truncate-test").info("new-line")

        contents = log_path.read_text(encoding="utf-8")
        assert "new-line" in contents
        assert "old-line" not in contents

        lastsession_contents = lastsession_path.read_text(encoding="utf-8")
        assert "old-line" in lastsession_contents
        assert "older-line" not in lastsession_contents


def test_udp_receiver_serves_bounded_admin_log_query():
    receiver = UdpLogReceiver("127.0.0.1:0")
    port = receiver._socket.getsockname()[1]
    from obstacle_bridge import bridge_debug_logging

    original_ring = bridge_debug_logging.DEBUG_LOG_RING
    bridge_debug_logging.DEBUG_LOG_RING = type(original_ring)(["first", "last"], maxlen=original_ring.maxlen)
    try:
        receiver._socket.setblocking(True)

        def serve_one():
            data, address = receiver._socket.recvfrom(receiver.max_datagram_bytes)
            receiver.handle_datagram(data, address)

        thread = threading.Thread(target=serve_one)
        thread.start()
        assert UdpLogQueryClient("127.0.0.1:%s" % port, timeout_sec=0.2).fetch(limit=1) == {
            "available": True, "lines": ["last"], "error": ""
        }
        thread.join(timeout=1)
    finally:
        bridge_debug_logging.DEBUG_LOG_RING = original_ring
        receiver._socket.close()


def test_udp_log_sender_drops_transport_failure_without_raising():
    handler = NonBlockingUdpLogHandler("127.0.0.1:15140")
    try:
        original_socket = handler._socket
        handler._socket = mock.Mock(send=mock.Mock(side_effect=BlockingIOError))
        handler.emit(logging.makeLogRecord({"name": "test", "msg": "fast path", "levelno": logging.INFO}))
        handler._socket = original_socket
        assert handler.dropped_records == 1
    finally:
        handler.close()


def test_admin_logs_udp_only_reports_logger_unavailable_without_runner_call():
    ui = AdminWebUI(SimpleNamespace(log_udp_only=True), mock.Mock())
    ui._send_json = mock.AsyncMock()
    ui._log_api_response = mock.Mock()
    ui._call_runner = mock.Mock()
    with mock.patch(
        "obstacle_bridge.bridge_logging_ipc.fetch_remote_log_lines",
        return_value={"available": False, "lines": [], "error": "logger unavailable"},
    ):
        asyncio.run(ui._handle_logs(mock.Mock(), "/api/logs?limit=10"))
    ui._call_runner.assert_not_called()
    assert ui._send_json.await_args.args[2] == {
        "ok": True, "lines": [], "count": 0, "source": "remote_udp",
        "logger_available": False, "logger_error": "logger unavailable",
    }


def test_admin_telemetry_status_is_redacted_and_reports_worker_liveness(tmp_path):
    from obstacle_bridge.bridge_telemetry import TelemetrySpool

    spool = TelemetrySpool(str(tmp_path / "spool"))
    assert spool.append({"v": 1, "kind": "telemetry.event", "installation_id": "install", "session_id": "session", "sequence": 1, "monotonic_ns": 1, "wall_time": 1.0, "priority": "normal", "event": "runtime.load", "fields": {"queue_depth": 1}})
    runner = mock.Mock()
    runner.get_telemetry_client_snapshot.return_value = {"enabled": True, "worker_state": "running"}
    ui = AdminWebUI(SimpleNamespace(telemetry_spool_directory=str(spool.directory)), runner)
    ui._send_json = mock.AsyncMock(); ui._log_api_response = mock.Mock(); ui._call_runner = mock.Mock()
    asyncio.run(ui._handle_telemetry(mock.Mock()))
    ui._call_runner.assert_called_once_with(runner.get_telemetry_client_snapshot, timeout=0.2)
    payload = ui._send_json.await_args.args[2]
    assert payload["ok"] and payload["telemetry"]["pending_events"] == 1
    assert "installation_id" not in payload["telemetry"]
    assert payload["client"] == ui._call_runner.return_value
