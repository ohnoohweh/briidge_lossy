#!/usr/bin/env python3
import argparse
import asyncio
import base64
import io
import signal
import tempfile
import unittest
from unittest import mock

from obstacle_bridge.bridge import Runner, RESTART_EXIT_CODE_DELAYED, RESTART_EXIT_CODE_IMMEDIATE
import obstacle_bridge.bridge_runner as bridge_runner


class RunnerEventBindingTests(unittest.IsolatedAsyncioTestCase):
    def _make_args(self):
        return argparse.Namespace(
            no_dashboard=True,
            udp_bind='0.0.0.0',
            udp_own_port=4433,
            overlay_transport='tcp',
            status=False,
        )

    async def test_shutdown_event_binds_to_running_loop(self):
        runner = Runner(self._make_args())
        with mock.patch.object(bridge_runner.logging, "getLogger") as get_logger:
            root_log = mock.Mock()
            get_logger.return_value = root_log
            runner.request_shutdown(reason="unit-test")

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._stop)
        self.assertTrue(runner._stop.is_set())
        self.assertEqual(runner._shutdown_reason, "unit-test")
        root_log.warning.assert_called_with("[RUNNER] shutdown requested reason=%s", "unit-test")
        await asyncio.wait_for(runner._stop.wait(), timeout=0.1)

    async def test_restart_event_binds_to_running_loop(self):
        runner = Runner(self._make_args())
        with mock.patch.object(bridge_runner.logging, "getLogger") as get_logger:
            root_log = mock.Mock()
            get_logger.return_value = root_log
            runner.request_restart(reason="unit-test")

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._restart_requested)
        self.assertTrue(runner._restart_requested.is_set())
        self.assertEqual(runner._restart_reason, "unit-test")
        root_log.warning.assert_called_with("[RUNNER] restart requested reason=%s", "unit-test")
        await asyncio.wait_for(runner._restart_requested.wait(), timeout=0.1)
        self.assertEqual(runner._restart_exit_code, RESTART_EXIT_CODE_IMMEDIATE)

    async def test_restart_event_uses_delayed_exit_code_for_myudp(self):
        args = self._make_args()
        args.overlay_transport = 'myudp'
        runner = Runner(args)
        runner.request_restart(reason="unit-test")

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._restart_requested)
        self.assertTrue(runner._restart_requested.is_set())
        self.assertEqual(runner._restart_reason, "unit-test")
        await asyncio.wait_for(runner._restart_requested.wait(), timeout=0.1)
        self.assertEqual(runner._restart_exit_code, RESTART_EXIT_CODE_DELAYED)


if __name__ == '__main__':
    unittest.main()


class RunnerDebugLogTests(unittest.TestCase):
    def _make_args(self):
        return argparse.Namespace(
            no_dashboard=True,
            udp_bind='0.0.0.0',
            udp_own_port=4433,
            overlay_transport='tcp',
            status=False,
            log_file='',
        )

    def test_get_debug_logs_falls_back_to_log_file_when_ring_is_empty(self):
        args = self._make_args()
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=True) as handle:
            handle.write("line-1\nline-2\nline-3\n")
            handle.flush()
            args.log_file = handle.name
            runner = Runner(args)
            original_ring = bridge_runner.DEBUG_LOG_RING
            bridge_runner.DEBUG_LOG_RING = type(original_ring)([], maxlen=original_ring.maxlen)
            try:
                self.assertEqual(runner.get_debug_logs(limit=2), ["line-2", "line-3"])
            finally:
                bridge_runner.DEBUG_LOG_RING = original_ring


class RunnerProcessBreadcrumbTests(unittest.TestCase):
    def _make_args(self):
        return argparse.Namespace(
            no_dashboard=True,
            udp_bind='0.0.0.0',
            udp_own_port=4433,
            overlay_transport='tcp',
            status=False,
            log_file='',
        )

    def test_install_process_signal_handlers_requests_shutdown(self):
        runner = Runner(self._make_args())
        log = mock.Mock()
        installed_handlers = {}

        def _fake_signal(signum, handler):
            installed_handlers[int(signum)] = handler
            return None

        with mock.patch.object(bridge_runner._process_signal, "getsignal", return_value="previous"), \
             mock.patch.object(bridge_runner._process_signal, "signal", side_effect=_fake_signal):
            installed = bridge_runner._install_process_signal_handlers(runner, log)

        self.assertEqual(sorted(signum for signum, _ in installed), sorted([int(signal.SIGINT), int(signal.SIGTERM)]))
        installed_handlers[int(signal.SIGTERM)](int(signal.SIGTERM), None)
        self.assertTrue(runner._stop_requested)
        self.assertEqual(runner._shutdown_exit_code, 128 + int(signal.SIGTERM))
        self.assertEqual(runner._shutdown_reason, "signal:SIGTERM")
        log.warning.assert_called_with(
            "[RUNNER] process signal received signum=%d signame=%s exit_code=%d",
            int(signal.SIGTERM),
            bridge_runner._signal_name(int(signal.SIGTERM)),
            128 + int(signal.SIGTERM),
        )

    def test_main_logs_system_exit_code(self):
        args = self._make_args()
        fake_runner = mock.Mock()
        fake_runner._stop_requested = True
        fake_runner._shutdown_exit_code = 76
        fake_runner._shutdown_reason = "admin_web:/api/shutdown"
        fake_runner._restart_requested_flag = False
        fake_runner._restart_exit_code = bridge_runner.RESTART_EXIT_CODE_IMMEDIATE
        fake_runner._restart_reason = ""
        fake_runner.run.return_value = object()
        fake_log = mock.Mock()

        with mock.patch.object(bridge_runner, "parse_runtime_args", return_value=args), \
             mock.patch.object(bridge_runner, "Runner", return_value=fake_runner), \
             mock.patch.object(bridge_runner.logging, "getLogger", return_value=fake_log), \
             mock.patch.object(bridge_runner, "_install_process_signal_handlers", return_value=[]), \
             mock.patch.object(bridge_runner, "_restore_process_signal_handlers"), \
             mock.patch.object(bridge_runner.asyncio, "run", side_effect=SystemExit(76)):
            with self.assertRaises(SystemExit):
                bridge_runner.main(["--config", "ObstacleBridge.cfg"])

        fake_log.warning.assert_any_call(
            "[RUNNER] process exit via SystemExit code=%r stop_requested=%s shutdown_rc=%r shutdown_reason=%r restart_requested=%s restart_rc=%r restart_reason=%r",
            76,
            True,
            76,
            "admin_web:/api/shutdown",
            False,
            bridge_runner.RESTART_EXIT_CODE_IMMEDIATE,
            "",
        )

    def test_linux_tun_elevation_exec_argv_preserves_runtime_env_names(self):
        cmd = bridge_runner._linux_tun_elevation_exec_argv(["--config", "ObstacleBridge.cfg"])

        self.assertEqual(cmd[:2], ["sudo", "-E"])
        self.assertIn("--preserve-env=OBSTACLEBRIDGE_LINUX_TUN_ELEVATED,OBSTACLEBRIDGE_MACOS_TUN_ELEVATED,PYTHONPATH,VIRTUAL_ENV", cmd)
        self.assertEqual(cmd[3:6], [bridge_runner.sys.executable, "-m", "obstacle_bridge.bridge_runner"])

    def test_main_reexecs_with_linux_tun_privileges_when_local_tun_requires_root(self):
        args = self._make_args()
        fake_log = mock.Mock()

        with mock.patch.object(bridge_runner, "parse_runtime_args", return_value=args), \
             mock.patch.object(bridge_runner.logging, "getLogger", return_value=fake_log), \
             mock.patch.object(bridge_runner.sys, "platform", "linux"), \
             mock.patch.object(bridge_runner.os, "geteuid", return_value=1000), \
             mock.patch.object(bridge_runner, "_configured_local_tun_services", return_value=[object()]), \
             mock.patch.object(bridge_runner, "_configured_packetflow_connector_mode", return_value=""), \
             mock.patch.object(bridge_runner.shutil, "which", return_value="/usr/bin/sudo"), \
             mock.patch.object(bridge_runner.os, "execvpe", side_effect=SystemExit(0)) as execvpe, \
             mock.patch.object(bridge_runner, "Runner") as runner_cls, \
             mock.patch.object(bridge_runner.asyncio, "run") as asyncio_run:
            with self.assertRaises(SystemExit) as exc:
                bridge_runner.main(["--config", "ObstacleBridge.cfg"])

        self.assertEqual(exc.exception.code, 0)
        runner_cls.assert_not_called()
        asyncio_run.assert_not_called()
        execvpe.assert_called_once()
        self.assertEqual(execvpe.call_args.args[0], "/usr/bin/sudo")
        self.assertIn("--preserve-env=OBSTACLEBRIDGE_LINUX_TUN_ELEVATED", execvpe.call_args.args[1][2])
        self.assertEqual(execvpe.call_args.args[2]["OBSTACLEBRIDGE_LINUX_TUN_ELEVATED"], "1")

    def test_macos_tun_reexec_prints_notice_before_sudo_password_prompt(self):
        fake_log = mock.Mock()
        stderr = io.StringIO()

        with mock.patch.object(bridge_runner.shutil, "which", return_value="/usr/bin/sudo"), \
             mock.patch.object(bridge_runner.sys, "stderr", stderr), \
             mock.patch.object(bridge_runner.os, "execvpe", side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                bridge_runner._maybe_reexec_with_sudo_tun_privileges(
                    argv=["--config", "ObstacleBridge.cfg"],
                    log=fake_log,
                    notice=(
                        "ObstacleBridge needs elevated privileges to create/configure the local macOS TUN device. "
                        "sudo may now ask for your password."
                    ),
                    marker_env="OBSTACLEBRIDGE_MACOS_TUN_ELEVATED",
                    cmd=bridge_runner._macos_tun_elevation_exec_argv(["--config", "ObstacleBridge.cfg"]),
                    platform_name="macOS",
                )

        self.assertIn("sudo may now ask for your password", stderr.getvalue())

    def test_main_reexecs_with_windows_tun_privileges_when_local_tun_requires_admin(self):
        args = self._make_args()
        fake_log = mock.Mock()
        shell32 = mock.Mock()
        shell32.ShellExecuteW.return_value = 42

        with mock.patch.dict(bridge_runner.os.environ, {"WINTUN_DIR": r"C:\Users\me\wintun\bin\amd64"}, clear=False):
            with mock.patch.object(bridge_runner, "parse_runtime_args", return_value=args), \
                 mock.patch.object(bridge_runner.logging, "getLogger", return_value=fake_log), \
                 mock.patch.object(bridge_runner.sys, "platform", "win32"), \
                 mock.patch.object(bridge_runner, "_configured_local_tun_services", return_value=[object()]), \
                 mock.patch.object(bridge_runner, "_configured_packetflow_connector_mode", return_value=""), \
                 mock.patch.object(bridge_runner, "_is_windows_admin", return_value=False), \
                 mock.patch.object(bridge_runner.ctypes, "windll", mock.Mock(shell32=shell32), create=True), \
                 mock.patch.object(bridge_runner, "Runner") as runner_cls, \
                 mock.patch.object(bridge_runner.asyncio, "run") as asyncio_run:
                with self.assertRaises(SystemExit) as exc:
                    bridge_runner.main(["--config", "ObstacleBridge.cfg"])

        self.assertEqual(exc.exception.code, 0)
        runner_cls.assert_not_called()
        asyncio_run.assert_not_called()
        shell32.ShellExecuteW.assert_called_once()
        self.assertEqual(shell32.ShellExecuteW.call_args.args[1], "runas")
        self.assertEqual(shell32.ShellExecuteW.call_args.args[2], "powershell.exe")
        encoded = shell32.ShellExecuteW.call_args.args[3].split()[-1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("$env:OBSTACLEBRIDGE_WINDOWS_TUN_ELEVATED = '1'", script)
        self.assertIn("$env:WINTUN_DIR = 'C:\\Users\\me\\wintun\\bin\\amd64'", script)
        self.assertIn("obstacle_bridge.bridge_runner", script)

    def test_main_skips_windows_reexec_when_already_admin(self):
        args = self._make_args()
        fake_log = mock.Mock()
        fake_runner = mock.Mock()
        fake_runner._stop_requested = False
        fake_runner._shutdown_exit_code = None
        fake_runner._shutdown_reason = ""
        fake_runner._restart_requested_flag = False
        fake_runner._restart_exit_code = bridge_runner.RESTART_EXIT_CODE_IMMEDIATE
        fake_runner._restart_reason = ""
        shell32 = mock.Mock()

        with mock.patch.object(bridge_runner, "parse_runtime_args", return_value=args), \
             mock.patch.object(bridge_runner.logging, "getLogger", return_value=fake_log), \
             mock.patch.object(bridge_runner.sys, "platform", "win32"), \
             mock.patch.object(bridge_runner, "_configured_local_tun_services", return_value=[object()]), \
             mock.patch.object(bridge_runner, "_configured_packetflow_connector_mode", return_value=""), \
             mock.patch.object(bridge_runner, "_is_windows_admin", return_value=True), \
             mock.patch.object(bridge_runner.ctypes, "windll", mock.Mock(shell32=shell32), create=True), \
             mock.patch.object(bridge_runner, "Runner", return_value=fake_runner), \
             mock.patch.object(bridge_runner, "_install_process_signal_handlers", return_value=[]), \
             mock.patch.object(bridge_runner, "_restore_process_signal_handlers"), \
             mock.patch.object(bridge_runner.asyncio, "run", return_value=None) as asyncio_run:
            bridge_runner.main(["--config", "ObstacleBridge.cfg"])

        shell32.ShellExecuteW.assert_not_called()
        asyncio_run.assert_called_once()

    def test_windows_tun_elevation_shell_execute_omits_wintun_dir_when_unset(self):
        with mock.patch.dict(bridge_runner.os.environ, {}, clear=True), \
             mock.patch.object(bridge_runner.sys, "executable", r"C:\Python\python.exe"):
            executable, params = bridge_runner._windows_tun_elevation_shell_execute(["--config", "ObstacleBridge.cfg"])

        self.assertEqual(executable, "powershell.exe")
        encoded = params.split()[-1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("$env:OBSTACLEBRIDGE_WINDOWS_TUN_ELEVATED = '1'", script)
        self.assertNotIn("WINTUN_DIR", script)
        self.assertIn(r"C:\Python\python.exe", script)
