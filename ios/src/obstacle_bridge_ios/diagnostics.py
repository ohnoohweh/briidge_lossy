"""Small iOS diagnostics helpers for lifecycle and termination analysis."""

from __future__ import annotations

import atexit
import faulthandler
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Mapping

from obstacle_bridge.bridge import _detect_build_info
from obstacle_bridge.crypto_extract import available_crypto_extract


_HOOKS_INSTALLED = False
def diagnostics_root(documents_root: Path) -> Path:
    root = Path(documents_root) / "logs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def event_log_path(documents_root: Path) -> Path:
    return diagnostics_root(documents_root) / "ios-diagnostics.jsonl"


def provider_log_path(documents_root: Path) -> Path:
    return diagnostics_root(documents_root) / "ipserver-native-provider.jsonl"


def _json_default(value: Any) -> str:
    return repr(value)


def log_event(documents_root: Path, event: str, **fields: Any) -> None:
    """Append one structured diagnostic event.

    The file is intentionally JSONL so a terminated app still leaves useful,
    append-only breadcrumbs without needing a clean shutdown.
    """
    payload = {
        "ts": time.time(),
        "pid": os.getpid(),
        "event": str(event),
        "build": _detect_build_info(),
        **fields,
    }
    try:
        append_jsonl(event_log_path(documents_root), payload)
    except Exception:
        pass


def append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(dict(payload), sort_keys=True, default=_json_default) + "\n")


def log_provider_event(documents_root: Path, event: str, **fields: Any) -> None:
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": os.getpid(),
        "native_event": str(event),
        "source": "python",
        "build": _detect_build_info(),
        **fields,
    }
    try:
        append_jsonl(provider_log_path(documents_root), payload)
    except Exception:
        pass


def install_crash_hooks(documents_root: Path) -> None:
    global _HOOKS_INSTALLED
    if _HOOKS_INSTALLED:
        return
    _HOOKS_INSTALLED = True
    root = Path(documents_root)
    diagnostics_root(root)

    try:
        fault_file = (diagnostics_root(root) / "python-faulthandler.log").open("a", encoding="utf-8")
        faulthandler.enable(file=fault_file, all_threads=True)
    except Exception:
        pass

    original_excepthook = sys.excepthook
    original_threading_hook = getattr(threading, "excepthook", None)
    original_unraisable_hook = getattr(sys, "unraisablehook", None)

    def _excepthook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        log_event(
            root,
            "python.unhandled_exception",
            error_type=getattr(exc_type, "__name__", str(exc_type)),
            error=str(exc),
            traceback="".join(traceback.format_exception(exc_type, exc, tb)),
        )
        original_excepthook(exc_type, exc, tb)

    def _threading_excepthook(args: threading.ExceptHookArgs) -> None:
        log_event(
            root,
            "python.thread_exception",
            thread=getattr(args.thread, "name", ""),
            error_type=getattr(args.exc_type, "__name__", str(args.exc_type)),
            error=str(args.exc_value),
            traceback="".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)),
        )
        if original_threading_hook is not None:
            original_threading_hook(args)

    def _unraisable_hook(args: Any) -> None:
        log_event(
            root,
            "python.unraisable_exception",
            object=repr(getattr(args, "object", "")),
            error_type=getattr(getattr(args, "exc_type", None), "__name__", str(getattr(args, "exc_type", ""))),
            error=str(getattr(args, "exc_value", "")),
            traceback="".join(
                traceback.format_exception(
                    getattr(args, "exc_type", None),
                    getattr(args, "exc_value", None),
                    getattr(args, "exc_traceback", None),
                )
            ),
        )
        if original_unraisable_hook is not None:
            original_unraisable_hook(args)

    sys.excepthook = _excepthook
    if original_threading_hook is not None:
        threading.excepthook = _threading_excepthook
    if original_unraisable_hook is not None:
        sys.unraisablehook = _unraisable_hook

    atexit.register(lambda: log_event(root, "python.atexit"))
    log_event(root, "python.diagnostics_hooks_installed", crypto_extract=available_crypto_extract())


def snapshot(documents_root: Path, *, max_events: int = 40) -> dict[str, Any]:
    root = Path(documents_root)
    events: list[Mapping[str, Any] | str] = []
    path = event_log_path(root)
    if path.exists():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[-max_events:]:
                try:
                    events.append(json.loads(line))
                except Exception:
                    events.append(line)
        except Exception as exc:
            events.append({"error": str(exc)})
    return {
        "documents_root": str(root),
        "event_log": str(path),
        "events": events,
        "build": _detect_build_info(),
        "crypto_extract": available_crypto_extract(),
    }
