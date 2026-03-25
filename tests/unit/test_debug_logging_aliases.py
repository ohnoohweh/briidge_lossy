import argparse
import logging

from obstacle_bridge.bridge import ConfigAwareCLI, DebugLoggingConfigurator


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
