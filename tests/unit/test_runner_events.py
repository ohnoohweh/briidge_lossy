#!/usr/bin/env python3
import argparse
import asyncio
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
        runner.request_shutdown(reason="unit-test")

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._stop)
        self.assertTrue(runner._stop.is_set())
        self.assertEqual(runner._shutdown_reason, "unit-test")
        await asyncio.wait_for(runner._stop.wait(), timeout=0.1)

    async def test_restart_event_binds_to_running_loop(self):
        runner = Runner(self._make_args())
        runner.request_restart(reason="unit-test")

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._restart_requested)
        self.assertTrue(runner._restart_requested.is_set())
        self.assertEqual(runner._restart_reason, "unit-test")
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
