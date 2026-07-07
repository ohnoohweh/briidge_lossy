#!/usr/bin/env python3
import asyncio
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from obstacle_bridge.bridge import Runner, SessionMetrics, build_runtime_args_from_config
import obstacle_bridge.bridge_runner as bridge_runner


class _FakeSession:
    def __init__(self) -> None:
        self.peer_proto = "udp"

    def set_on_state_change(self, _cb): pass
    def set_on_peer_rx(self, _cb): pass
    def set_on_peer_tx(self, _cb): pass
    def set_on_peer_set(self, _cb): pass
    def set_on_transport_epoch_change(self, _cb): pass
    async def start(self): return None
    async def stop(self): return None
    def is_connected(self) -> bool: return False
    def get_metrics(self): return SessionMetrics()


class _FakeMux:
    def __init__(self, *, on_stop=None) -> None:
        self._on_stop = on_stop

    def udp_open_count(self) -> int: return 0
    def tcp_open_count(self) -> int: return 0
    def tun_open_count(self) -> int: return 0
    async def start(self): return None
    async def stop(self, reason: str = ""):
        if self._on_stop is not None:
            result = self._on_stop(reason)
            if asyncio.iscoroutine(result):
                await result
        return None
    def snapshot_connections(self) -> dict:
        return {
            "udp": [],
            "tcp": [],
            "tun": [],
            "counts": {"udp": 0, "tcp": 0, "tun": 0, "udp_listening": 0, "tcp_listening": 0, "tun_listening": 0},
        }


class RunnerTunHelperTests(unittest.IsolatedAsyncioTestCase):
    def _helper_args(self):
        helper_dir = tempfile.mkdtemp(prefix="obstaclebridge-test-tun-helper-")
        self.addCleanup(lambda: shutil.rmtree(helper_dir, ignore_errors=True))
        return build_runtime_args_from_config(
            {
                "admin_web": False,
                "status": False,
                "tun_execution": {
                    "mode": "helper",
                    "helper_backend": "linux-python",
                    "helper_socket": os.path.join(helper_dir, "helper.sock"),
                    "helper_apply_network": True,
                },
            }
        )

    async def test_runner_starts_tun_helper_and_exposes_status_snapshot(self):
        args = self._helper_args()
        runner = Runner(args)
        fake_session = _FakeSession()
        fake_mux = _FakeMux()

        with mock.patch.object(bridge_runner.Runner, "build_sessions_from_overlay", return_value=[("fake", fake_session)]), \
             mock.patch.object(bridge_runner.ChannelMux, "from_args", return_value=fake_mux):
            await runner.start()
            try:
                self.assertIsNotNone(runner._tun_helper_client)
                self.assertIs(args._tun_helper_client, runner._tun_helper_client)
                self.assertIsNotNone(runner._tun_helper_process)
                opened = await runner._tun_helper_client.open_tun({"ifname": "obtun0", "mtu": 1400})
                applied = await runner._tun_helper_client.apply_network({"ifname": "obtun0", "mtu": 1400})
                snapshot = await runner._tun_helper_client.snapshot()
                status = runner.get_status_snapshot()
            finally:
                await runner.stop(reason="unit-test")

        self.assertEqual(opened["ifname"], "obtun0")
        self.assertEqual(opened["mtu"], 1400)
        self.assertTrue(applied["applied"])
        self.assertEqual(snapshot["backend"], "linux-python-memory")
        self.assertEqual(snapshot["apply_calls"], 1)
        self.assertFalse(hasattr(args, "_tun_helper_client"))
        self.assertFalse(hasattr(args, "_tun_helper_backend"))
        self.assertTrue(status["tun_helper"]["enabled"])
        self.assertTrue(status["tun_helper"]["connected"])
        self.assertTrue(status["tun_helper"]["server_started"])
        self.assertEqual(status["tun_helper"]["lifecycle_phase"], "connected")
        self.assertGreater(status["tun_helper"]["pid"], 0)
        self.assertEqual(status["tun_helper"]["runtime"]["backend"], "linux-python-memory")
        self.assertEqual(status["tun_helper"]["runtime"]["ifname"], "obtun0")

    async def test_runner_rejects_helper_mode_on_unsupported_platform(self):
        args = self._helper_args()
        runner = Runner(args)

        with mock.patch.object(bridge_runner.sys, "platform", "win32"), \
             mock.patch.object(bridge_runner.Runner, "build_sessions_from_overlay", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "currently supported only on Linux and macOS"):
                await runner.start()

    async def test_launch_tun_helper_process_uses_sudo_for_native_backend_when_unprivileged(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)
        runner._tun_helper_socket_path = "/tmp/obstaclebridge-helper.sock"
        runner._tun_helper_session_token = "secret-token"

        fake_proc = mock.Mock()
        with mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=1000), \
             mock.patch.object(bridge_runner, "_linux_native_tun_helper_can_launch_without_sudo", return_value=False), \
             mock.patch.object(bridge_runner.shutil, "which", return_value="/usr/bin/sudo"), \
             mock.patch.object(bridge_runner.asyncio, "create_subprocess_exec", new=mock.AsyncMock(return_value=fake_proc)) as create_exec:
            proc = await runner._launch_tun_helper_process()

        self.assertIs(proc, fake_proc)
        cmd = list(create_exec.await_args.args)
        self.assertEqual(cmd[:2], ["sudo", "-E"])
        self.assertIn("--preserve-env=PYTHONPATH,VIRTUAL_ENV,XDG_RUNTIME_DIR", cmd[2])
        self.assertEqual(cmd[3:6], [bridge_runner.sys.executable, "-m", "obstacle_bridge.bridge_tun_helper_server"])
        self.assertIn("--config-path", cmd)
        config_path = cmd[cmd.index("--config-path") + 1]
        with open(config_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["backend"], "linux-native")
        self.assertEqual(payload["socket_path"], "/tmp/obstaclebridge-helper.sock")
        self.assertEqual(payload["session_token"], "secret-token")
        self.assertEqual(payload["log_level"], str(args.tun_helper_log_level or "INFO"))
        runner._cleanup_tun_helper_launch_config()

    async def test_launch_tun_helper_process_skips_sudo_when_python_has_linux_capability(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)
        runner._tun_helper_socket_path = "/tmp/obstaclebridge-helper.sock"
        runner._tun_helper_session_token = "secret-token"

        fake_proc = mock.Mock()
        with mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=1000), \
             mock.patch.object(bridge_runner, "_linux_native_tun_helper_can_launch_without_sudo", return_value=True), \
             mock.patch.object(bridge_runner.asyncio, "create_subprocess_exec", new=mock.AsyncMock(return_value=fake_proc)) as create_exec:
            proc = await runner._launch_tun_helper_process()

        self.assertIs(proc, fake_proc)
        cmd = list(create_exec.await_args.args)
        self.assertEqual(cmd[:3], [bridge_runner.sys.executable, "-m", "obstacle_bridge.bridge_tun_helper_server"])
        self.assertNotIn("sudo", cmd)
        self.assertIn("--config-path", cmd)
        runner._cleanup_tun_helper_launch_config()

    async def test_launch_tun_helper_process_uses_sudo_for_darwin_native_backend_when_unprivileged(self):
        args = self._helper_args()
        args.tun_helper_backend = "darwin-native"
        runner = Runner(args)
        runner._tun_helper_socket_path = "/tmp/obstaclebridge-helper.sock"
        runner._tun_helper_session_token = "secret-token"

        fake_proc = mock.Mock()
        with mock.patch.object(bridge_runner.sys, "platform", "darwin"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=501), \
             mock.patch.object(bridge_runner.shutil, "which", return_value="/usr/bin/sudo"), \
             mock.patch.object(bridge_runner.asyncio, "create_subprocess_exec", new=mock.AsyncMock(return_value=fake_proc)) as create_exec:
            proc = await runner._launch_tun_helper_process()

        self.assertIs(proc, fake_proc)
        cmd = list(create_exec.await_args.args)
        self.assertEqual(cmd[:2], ["sudo", "-E"])
        self.assertIn("--preserve-env=PYTHONPATH,VIRTUAL_ENV,XDG_RUNTIME_DIR", cmd[2])
        self.assertEqual(cmd[3:6], [bridge_runner.sys.executable, "-m", "obstacle_bridge.bridge_tun_helper_server"])
        self.assertIn("--config-path", cmd)
        config_path = cmd[cmd.index("--config-path") + 1]
        with open(config_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["backend"], "darwin-native")
        self.assertEqual(payload["socket_path"], "/tmp/obstaclebridge-helper.sock")
        self.assertEqual(payload["session_token"], "secret-token")
        runner._cleanup_tun_helper_launch_config()

    def test_linux_native_tun_helper_can_launch_without_sudo_when_file_capabilities_present(self):
        with mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner, "_linux_effective_capability_names", return_value=set()), \
             mock.patch.object(bridge_runner, "_linux_executable_capability_names", return_value={"cap_net_admin"}):
            self.assertTrue(bridge_runner._linux_native_tun_helper_can_launch_without_sudo("/usr/bin/python3"))

    def test_linux_native_tun_helper_requires_sudo_without_effective_or_file_capabilities(self):
        with mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner, "_linux_effective_capability_names", return_value=set()), \
             mock.patch.object(bridge_runner, "_linux_executable_capability_names", return_value=set()):
            self.assertFalse(bridge_runner._linux_native_tun_helper_can_launch_without_sudo("/usr/bin/python3"))

    def test_tun_helper_socket_ready_timeout_extends_for_sudo_prompt(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)

        with mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=1000), \
             mock.patch.object(bridge_runner, "_linux_native_tun_helper_can_launch_without_sudo", return_value=False):
            self.assertEqual(runner._tun_helper_socket_ready_timeout_s(), 30.0)

    def test_tun_helper_socket_ready_timeout_stays_short_without_sudo(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)

        with mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=1000), \
             mock.patch.object(bridge_runner, "_linux_native_tun_helper_can_launch_without_sudo", return_value=True):
            self.assertEqual(runner._tun_helper_socket_ready_timeout_s(), 2.0)

    def test_tun_helper_socket_ready_timeout_extends_for_darwin_sudo_prompt(self):
        args = self._helper_args()
        args.tun_helper_backend = "darwin-native"
        runner = Runner(args)

        with mock.patch.object(bridge_runner.sys, "platform", "darwin"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=501):
            self.assertEqual(runner._tun_helper_socket_ready_timeout_s(), 30.0)

    def test_macos_tun_elevation_skips_whole_runtime_reexec_when_helper_mode_enabled(self):
        args = build_runtime_args_from_config(
            {
                "own_servers": [{"listen": {"protocol": "tun", "ifname": "obtun0"}}],
                "tun_execution": {"mode": "helper", "helper_backend": "darwin-native"},
            }
        )

        with mock.patch.object(bridge_runner.sys, "platform", "darwin"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=501), \
             mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(bridge_runner._needs_macos_tun_elevation(args))

    async def test_runner_status_reports_post_start_helper_disconnect(self):
        args = self._helper_args()
        runner = Runner(args)
        fake_session = _FakeSession()
        fake_mux = _FakeMux()

        with mock.patch.object(bridge_runner.Runner, "build_sessions_from_overlay", return_value=[("fake", fake_session)]), \
             mock.patch.object(bridge_runner.ChannelMux, "from_args", return_value=fake_mux):
            await runner.start()
            try:
                self.assertIsNotNone(runner._tun_helper_client)
                self.assertIsNotNone(runner._tun_helper_process)
                await runner._tun_helper_client.open_tun({"ifname": "obtun0", "mtu": 1400})
                runner._tun_helper_process.kill()
                await asyncio.wait_for(runner._tun_helper_process.wait(), timeout=1.0)
                await asyncio.sleep(0.1)
                status = runner.get_status_snapshot()
            finally:
                await runner.stop(reason="unit-test")

        self.assertTrue(status["tun_helper"]["enabled"])
        self.assertFalse(status["tun_helper"]["connected"])
        self.assertFalse(status["tun_helper"]["server_started"])
        self.assertEqual(status["tun_helper"]["lifecycle_phase"], "process_exited")
        self.assertIsInstance(status["tun_helper"]["process_returncode"], int)
        self.assertIn("connection closed", status["tun_helper"]["last_error"].lower())
        self.assertEqual(status["tun_helper"]["runtime"]["ifname"], "obtun0")
        self.assertFalse(status["tun_helper"].get("recovery"))

    def test_runner_status_reports_helper_recovery_warning_when_cached_runtime_may_need_cleanup(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)
        runner._tun_helper_last_error = "TUN helper connection closed"
        runner._tun_helper_runtime_snapshot = {
            "backend": "linux-native",
            "ifname": "obtun0",
            "firewall_manager": "iptables",
            "applied_firewall_rules": ["iptables -A FORWARD -i obtun0 -o eth0 -j ACCEPT"],
            "network_applied": True,
            "applied_ipv4_cidr": "198.18.40.1/24",
            "applied_ipv4_routes": ["198.18.41.0/24"],
        }
        runner._tun_helper_process = mock.Mock(pid=1234, returncode=92)
        runner._tun_helper_client = None

        status = runner.get_status_snapshot()

        recovery = dict(status["tun_helper"].get("recovery") or {})
        self.assertTrue(recovery["needs_manual_cleanup"])
        self.assertTrue(recovery["stale_firewall_possible"])
        self.assertTrue(recovery["stale_network_possible"])
        self.assertIn("firewall_rules_may_remain", recovery["warnings"])
        self.assertIn("helper_owned_network_state_may_remain", recovery["warnings"])
        self.assertIn("manual cleanup", recovery["repair_hint"].lower())

    def test_runner_request_tun_helper_repair_uses_linux_native_snapshot_cleanup(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)
        runner._tun_helper_last_error = "TUN helper connection closed"
        runner._tun_helper_runtime_snapshot = {
            "backend": "linux-native",
            "ifname": "obtun0",
            "firewall_manager": "iptables",
            "applied_firewall_rules": ["iptables -A FORWARD -i obtun0 -o eth0 -j ACCEPT"],
            "network_applied": True,
            "applied_ipv4_cidr": "198.18.40.1/24",
        }
        runner._tun_helper_process = mock.Mock(pid=1234, returncode=92)
        runner._tun_helper_client = None

        with mock.patch.object(
            bridge_runner.LinuxTunHelperBackend,
            "repair_runtime_snapshot",
            return_value={
                "ok": True,
                "repaired": ["firewall", "ipv4_addr"],
                "failed": [],
                "runtime": {"backend": "linux-native", "ifname": "obtun0", "network_applied": False, "firewall_manager": "", "applied_firewall_rules": []},
            },
        ) as repair_runtime_snapshot, \
             mock.patch.object(
                 bridge_runner.LinuxTunHelperBackend,
                 "verify_runtime_snapshot_repaired",
                 return_value={
                     "ok": True,
                     "checked": ["firewall", "ipv4_addr"],
                     "remaining": [],
                     "skipped": [],
                     "stale_state_remaining": False,
                     "summary": "Post-repair verification did not find remaining helper-owned host state.",
                 },
             ) as verify_runtime_snapshot_repaired:
            result = runner.request_tun_helper_repair()

        self.assertTrue(result["ok"])
        self.assertTrue(result["cleanup_ok"])
        self.assertEqual(result["repaired"], ["firewall", "ipv4_addr"])
        repair_runtime_snapshot.assert_called_once()
        verify_runtime_snapshot_repaired.assert_called_once()
        self.assertEqual(runner._tun_helper_runtime_snapshot["ifname"], "obtun0")
        self.assertEqual(runner._tun_helper_runtime_snapshot["firewall_manager"], "")
        helper_status = runner._tun_helper_snapshot()
        self.assertFalse(helper_status.get("recovery"))
        last_repair = dict(helper_status.get("last_repair") or {})
        self.assertTrue(last_repair["attempted"])
        self.assertTrue(last_repair["ok"])
        self.assertTrue(last_repair["cleanup_ok"])
        self.assertFalse(last_repair["stale_state_remaining"])
        self.assertEqual(last_repair["verified_state"], "stale_state_cleared")
        self.assertEqual(last_repair["verification"]["remaining"], [])
        self.assertIn("repair succeeded", last_repair["summary"].lower())

    def test_runner_request_tun_helper_repair_reports_remaining_stale_state_when_cleanup_incomplete(self):
        args = self._helper_args()
        args.tun_helper_backend = "linux-native"
        runner = Runner(args)
        runner._tun_helper_last_error = "TUN helper connection closed"
        runner._tun_helper_runtime_snapshot = {
            "backend": "linux-native",
            "ifname": "obtun0",
            "firewall_manager": "iptables",
            "applied_firewall_rules": ["iptables -A FORWARD -i obtun0 -o eth0 -j ACCEPT"],
            "network_applied": True,
            "applied_ipv4_cidr": "198.18.40.1/24",
        }
        runner._tun_helper_process = mock.Mock(pid=1234, returncode=92)
        runner._tun_helper_client = None

        with mock.patch.object(
            bridge_runner.LinuxTunHelperBackend,
            "repair_runtime_snapshot",
            return_value={
                "ok": False,
                "repaired": ["firewall"],
                "failed": [{"step": "ipv4_addr", "error": "busy", "error_type": "RuntimeError"}],
                "runtime": {},
            },
        ), \
             mock.patch.object(
                 bridge_runner.LinuxTunHelperBackend,
                 "verify_runtime_snapshot_repaired",
                 return_value={
                     "ok": False,
                     "checked": ["firewall", "ipv4_addr"],
                     "remaining": [{"step": "ipv4_addr", "detail": "198.18.40.1/24"}],
                     "skipped": [],
                     "stale_state_remaining": True,
                     "summary": "Post-repair verification could not confirm that all helper-owned host state was cleared.",
                 },
             ):
            result = runner.request_tun_helper_repair()

        self.assertFalse(result["ok"])
        self.assertFalse(result["cleanup_ok"])
        helper_status = runner._tun_helper_snapshot()
        self.assertTrue(helper_status.get("recovery"))
        last_repair = dict(helper_status.get("last_repair") or {})
        self.assertTrue(last_repair["attempted"])
        self.assertFalse(last_repair["ok"])
        self.assertFalse(last_repair["cleanup_ok"])
        self.assertTrue(last_repair["stale_state_remaining"])
        self.assertEqual(last_repair["verified_state"], "stale_state_may_remain")
        self.assertEqual(last_repair["verification"]["remaining"][0]["step"], "ipv4_addr")
        self.assertIn("may still remain", last_repair["summary"].lower())

    async def test_runner_stop_keeps_helper_available_until_mux_stop_finishes(self):
        args = self._helper_args()
        runner = Runner(args)
        fake_session = _FakeSession()
        helper_seen_during_mux_stop = {"value": False}

        async def _on_mux_stop(_reason: str) -> None:
            helper_seen_during_mux_stop["value"] = runner._tun_helper_client is not None

        fake_mux = _FakeMux(on_stop=_on_mux_stop)

        with mock.patch.object(bridge_runner.Runner, "build_sessions_from_overlay", return_value=[("fake", fake_session)]), \
             mock.patch.object(bridge_runner.ChannelMux, "from_args", return_value=fake_mux):
            await runner.start()
            await runner.stop(reason="unit-test")

        self.assertTrue(helper_seen_during_mux_stop["value"])
        self.assertIsNone(runner._tun_helper_client)


if __name__ == "__main__":
    unittest.main()
