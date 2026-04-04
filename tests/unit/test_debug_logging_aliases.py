import argparse
import logging

from obstacle_bridge.bridge import ConfigAwareCLI, DebugLoggingConfigurator, SecureLinkPskSession


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
