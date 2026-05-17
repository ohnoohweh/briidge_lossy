#!/usr/bin/env python3
import argparse
import asyncio
import tempfile
import unittest

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
        runner.request_shutdown()

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._stop)
        self.assertTrue(runner._stop.is_set())
        await asyncio.wait_for(runner._stop.wait(), timeout=0.1)

    async def test_restart_event_binds_to_running_loop(self):
        runner = Runner(self._make_args())
        runner.request_restart()

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._restart_requested)
        self.assertTrue(runner._restart_requested.is_set())
        await asyncio.wait_for(runner._restart_requested.wait(), timeout=0.1)
        self.assertEqual(runner._restart_exit_code, RESTART_EXIT_CODE_IMMEDIATE)

    async def test_restart_event_uses_delayed_exit_code_for_myudp(self):
        args = self._make_args()
        args.overlay_transport = 'myudp'
        runner = Runner(args)
        runner.request_restart()

        runner._ensure_runtime_events()

        self.assertIsNotNone(runner._restart_requested)
        self.assertTrue(runner._restart_requested.is_set())
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
