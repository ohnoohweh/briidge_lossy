#!/usr/bin/env python3
import argparse
import asyncio
import unittest

from obstacle_bridge.bridge import Runner


class RunnerEventBindingTests(unittest.IsolatedAsyncioTestCase):
    def _make_args(self):
        return argparse.Namespace(
            no_dashboard=True,
            bind443='0.0.0.0',
            port443=443,
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


if __name__ == '__main__':
    unittest.main()
