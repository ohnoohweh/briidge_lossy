from __future__ import annotations

import argparse
import os
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .bridge_tun_helper_local_transport import allocate_local_tcp_endpoint, is_local_tcp_endpoint


TUN_EXECUTION_SECTION = "tun_execution"
DEFAULT_TUN_EXECUTION_MODE = "inline"
DEFAULT_TUN_HELPER_BACKEND = "linux-native"
DEFAULT_TUN_HELPER_SOCKET = ""
DEFAULT_TUN_HELPER_APPLY_NETWORK = True
DEFAULT_TUN_HELPER_LOG_LEVEL = "INFO"
_TUN_EXECUTION_MODES = ("inline", "helper")


def _is_windows_helper_backend(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return normalized in {"windows-native", "windows_native", "wintun-native", "wintun_native"}


def _is_windows_pipe_path(path: str) -> bool:
    text = str(path or "").strip()
    return text.startswith("\\\\.\\pipe\\")


def _clean_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _runtime_user_fragment() -> str:
    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        try:
            return str(int(getuid()))
        except Exception:
            pass
    for env_name in ("USERNAME", "USER", "LOGNAME"):
        value = str(os.environ.get(env_name) or "").strip()
        if value:
            return value
    return "nouid"


def _text_value(
    values: Mapping[str, Any],
    key: str,
    default: str,
    *,
    allow_empty: bool = False,
) -> str:
    raw = values.get(key)
    if raw is None:
        return default
    text = str(raw).strip()
    if not text and not allow_empty:
        return default
    return text


@dataclass(frozen=True)
class TunExecutionSettings:
    mode: str = DEFAULT_TUN_EXECUTION_MODE
    helper_backend: str = DEFAULT_TUN_HELPER_BACKEND
    helper_socket: str = DEFAULT_TUN_HELPER_SOCKET
    helper_apply_network: bool = DEFAULT_TUN_HELPER_APPLY_NETWORK
    helper_log_level: str = DEFAULT_TUN_HELPER_LOG_LEVEL

    @staticmethod
    def register_cli(parser: argparse.ArgumentParser) -> None:
        group = parser.add_argument_group(TUN_EXECUTION_SECTION)
        group.add_argument(
            "--tun-execution-mode",
            choices=list(_TUN_EXECUTION_MODES),
            default=DEFAULT_TUN_EXECUTION_MODE,
            help="Desktop local TUN execution topology: inline current-process ownership or helper-backed ownership.",
        )
        group.add_argument(
            "--tun-helper-backend",
            default=DEFAULT_TUN_HELPER_BACKEND,
            help="Helper backend identifier for helper mode. Values include linux-native, linux-python, darwin-native, and windows-native.",
        )
        group.add_argument(
            "--tun-helper-socket",
            default=DEFAULT_TUN_HELPER_SOCKET,
            help="Optional explicit local IPC socket path for helper mode.",
        )
        group.add_argument(
            "--tun-helper-apply-network",
            action=argparse.BooleanOptionalAction,
            default=DEFAULT_TUN_HELPER_APPLY_NETWORK,
            help="Whether the helper should own privileged address/route/DNS/firewall apply-remove work.",
        )
        group.add_argument(
            "--log-tun-helper",
            dest="tun_helper_log_level",
            default=DEFAULT_TUN_HELPER_LOG_LEVEL,
            help="Log level for the TUN helper control path.",
        )

    @classmethod
    def from_mapping(
        cls,
        config: Optional[Mapping[str, Any]],
        *,
        base: Optional["TunExecutionSettings"] = None,
    ) -> "TunExecutionSettings":
        current = base if base is not None else cls()
        source: Mapping[str, Any] = config or {}
        group = source.get(TUN_EXECUTION_SECTION) if isinstance(source, Mapping) else None
        values = group if isinstance(group, Mapping) else source
        mode = _text_value(values, "tun_execution_mode", _text_value(values, "mode", current.mode)).lower()
        if mode not in _TUN_EXECUTION_MODES:
            mode = current.mode
        helper_backend = _text_value(
            values,
            "tun_helper_backend",
            _text_value(values, "helper_backend", current.helper_backend),
        )
        helper_socket = _text_value(
            values,
            "tun_helper_socket",
            _text_value(values, "helper_socket", current.helper_socket, allow_empty=True),
            allow_empty=True,
        )
        helper_apply_network = _clean_bool(
            values.get("tun_helper_apply_network", values.get("helper_apply_network")),
            default=current.helper_apply_network,
        )
        helper_log_level = _text_value(
            values,
            "tun_helper_log_level",
            _text_value(values, "helper_log_level", current.helper_log_level),
        ).upper()
        return cls(
            mode=mode,
            helper_backend=helper_backend,
            helper_socket=helper_socket,
            helper_apply_network=helper_apply_network,
            helper_log_level=helper_log_level,
        )

    def helper_mode_supported(self, *, platform: Optional[str] = None) -> bool:
        target = str(platform or sys.platform or "")
        if self.mode != "helper":
            return True
        if target.startswith("linux") or target.startswith("darwin"):
            return True
        if target.startswith("win"):
            return _is_windows_helper_backend(self.helper_backend)
        return False

    def ensure_supported_platform(self, *, platform: Optional[str] = None) -> None:
        if self.helper_mode_supported(platform=platform):
            return
        target = str(platform or sys.platform or "")
        raise RuntimeError(
            f"tun_execution.mode=helper is currently supported on Linux/macOS, and on Windows only for the windows-native backend; current platform is {target!r} with backend {self.helper_backend!r}."
        )

    def resolved_socket_path(self) -> str:
        explicit = str(self.helper_socket or "").strip()
        if explicit:
            return explicit
        if sys.platform.startswith("win") and _is_windows_helper_backend(self.helper_backend):
            return allocate_local_tcp_endpoint()
        socket_name = f"tun-helper-{os.getpid()}.sock"
        runtime_dir = str(os.environ.get("XDG_RUNTIME_DIR") or "").strip()
        if runtime_dir:
            if "/" in runtime_dir:
                return f"{runtime_dir.rstrip('/')}/obstaclebridge/{socket_name}"
            return os.path.join(runtime_dir, "obstaclebridge", socket_name)
        return os.path.join(
            tempfile.gettempdir(),
            f"obstaclebridge-{_runtime_user_fragment()}",
            socket_name,
        )

    def resolved_runtime_dir(self) -> str:
        explicit = str(self.helper_socket or "").strip()
        if explicit and not _is_windows_pipe_path(explicit) and not is_local_tcp_endpoint(explicit):
            return os.path.dirname(explicit) or tempfile.gettempdir()
        if sys.platform.startswith("win") and _is_windows_helper_backend(self.helper_backend):
            return os.path.join(tempfile.gettempdir(), "obstaclebridge-win-helper")
        runtime_dir = str(os.environ.get("XDG_RUNTIME_DIR") or "").strip()
        if runtime_dir:
            if "/" in runtime_dir:
                return f"{runtime_dir.rstrip('/')}/obstaclebridge"
            return os.path.join(runtime_dir, "obstaclebridge")
        return os.path.join(tempfile.gettempdir(), f"obstaclebridge-{_runtime_user_fragment()}")
