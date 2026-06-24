#!/usr/bin/env python3
import unittest

from obstacle_bridge.bridge_transport_common import EgressThroughputTracker


class EgressThroughputTrackerTests(unittest.TestCase):
    def test_tracker_rolls_previous_window_and_resets_current(self):
        tracker = EgressThroughputTracker(window_ns=100)

        tracker.record(300, now_ns=10)
        self.assertEqual(tracker.snapshot(now_ns=50), (0, 300))
        self.assertEqual(tracker.snapshot(now_ns=120), (300, 0))

        tracker.record(200, now_ns=130)
        self.assertEqual(tracker.snapshot(now_ns=180), (300, 200))
        self.assertEqual(tracker.snapshot(now_ns=250), (200, 0))


if __name__ == "__main__":
    unittest.main()
