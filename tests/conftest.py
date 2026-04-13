import os
from pathlib import Path
import socket
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-linux-elevated",
        action="store_true",
        default=False,
        help="run Linux-only elevated integration tests that require /dev/net/tun and interface-create permission",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    want_linux_elevated = bool(config.getoption("--run-linux-elevated"))
    if not want_linux_elevated:
        env_value = str(os.environ.get("OBSTACLEBRIDGE_RUN_LINUX_ELEVATED") or "").strip().lower()
        want_linux_elevated = env_value in {"1", "true", "yes", "on"}

    skip_linux_elevated = pytest.mark.skip(
        reason="linux_elevated tests require explicit opt-in via --run-linux-elevated or OBSTACLEBRIDGE_RUN_LINUX_ELEVATED=1"
    )
    socket_unavailable_reason = _local_socket_unavailable_reason()
    skip_integration_sockets = pytest.mark.skip(
        reason=f"integration tests require local socket support ({socket_unavailable_reason})"
    )
    for item in items:
        if "linux_elevated" in item.keywords and not want_linux_elevated:
            item.add_marker(skip_linux_elevated)
        if socket_unavailable_reason and "integration" in item.keywords:
            item.add_marker(skip_integration_sockets)


def _local_socket_unavailable_reason() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
    except OSError as exc:
        return f"{exc.__class__.__name__}: {exc}"
    return ""
