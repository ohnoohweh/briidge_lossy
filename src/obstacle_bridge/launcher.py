"""
Supervisor-style runtime entrypoint for ``python -m obstacle_bridge``.

This module parses launcher-specific options and forwards unknown CLI options
to ``bridge.py``.
"""

from __future__ import annotations

import argparse
import contextlib
import email.utils
import html
import importlib.util
import ipaddress
import json
import os
import pathlib
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple


PUBLIC_IP_DISCOVERY_SERVICES = (
    "https://4.ipw.cn",
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
)
PUBLIC_IP_DISCOVERY_TIMEOUT_S = 1.0
RUNTIME_DEPENDENCIES = ("aioquic", "cryptography", "websockets")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ObstacleBridge and restart on project restart exit codes"
    )
    parser.add_argument(
        "--command",
        default=None,
        help=(
            "Command to run (single string; shell-split). "
            "When omitted, the launcher starts: "
            "python -m obstacle_bridge.bridge --config ObstacleBridge.cfg"
        ),
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=30,
        help="Seconds to wait before restarting when exit code == 77",
    )
    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="Do not redirect stdout/stderr to the OS null device (useful for debugging)",
    )
    return parser


def _default_bridge_command(forward_args: Sequence[str]) -> List[str]:
    return [
        sys.executable,
        "-c",
        "from obstacle_bridge.bridge import main; main()",
        "--config",
        "ObstacleBridge.cfg",
        *list(forward_args),
    ]


def _resolve_command(raw_command: Optional[str], forward_args: Sequence[str]) -> List[str]:
    if raw_command:
        return [*shlex.split(raw_command), *list(forward_args)]
    return _default_bridge_command(forward_args)


def _missing_runtime_dependencies() -> List[str]:
    return [name for name in RUNTIME_DEPENDENCIES if importlib.util.find_spec(name) is None]


def _repo_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return here.parents[2]


def _maybe_offer_dependency_install(missing: Sequence[str]) -> bool:
    if not missing:
        return True
    names = ", ".join(missing)
    install_cmd = [sys.executable, "-m", "pip", "install", "-e", str(_repo_root())]
    hint = " ".join(shlex.quote(part) for part in install_cmd)
    print(f"Missing Python package dependencies: {names}", file=sys.stderr, flush=True)
    print(f"Install command: {hint}", file=sys.stderr, flush=True)
    if not sys.stdin.isatty():
        print("Non-interactive startup; continuing without installing dependencies.", file=sys.stderr, flush=True)
        return True
    try:
        answer = input("Would you like to start installation of dependent packages? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr, flush=True)
        return False
    if answer.strip().lower() not in {"y", "yes"}:
        print("Dependency installation skipped.", file=sys.stderr, flush=True)
        return True
    result = subprocess.run(install_cmd)
    if result.returncode != 0:
        print(f"Dependency installation failed with exit code {result.returncode}.", file=sys.stderr, flush=True)
        return False
    return True


def _build_bridge_notice_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", "-c", default="ObstacleBridge.cfg")
    parser.add_argument("--dump-config", nargs="?")
    parser.add_argument("--save-config")
    parser.add_argument("--admin-web", action="store_true", default=True)
    parser.add_argument("--admin-web-bind", default="127.0.0.1")
    parser.add_argument("--admin-web-port", type=int, default=18080)
    parser.add_argument("--admin-web-path", default="/")
    return parser


def _flatten_config(config: Dict[str, Any]) -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def _load_config_defaults(config_path: pathlib.Path, explicit_config: bool) -> Dict[str, Any]:
    if not explicit_config and not config_path.exists():
        return {}
    try:
        raw = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return _flatten_config(payload)


def _clickable_host(bind: str) -> str:
    host = str(bind or "").strip()
    if host in {"", "0.0.0.0", "::", "*", "localhost"}:
        return "127.0.0.1"
    return host


def _is_wildcard_bind(bind: str) -> bool:
    return str(bind or "").strip() in {"", "0.0.0.0", "::", "*"}


def _normalize_ip_literal(host: str) -> Optional[str]:
    value = str(host or "").strip()
    if not value:
        return None
    if "%" in value:
        value = value.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _rank_local_ip(host: str) -> Tuple[int, str]:
    ip_obj = ipaddress.ip_address(host)
    if ip_obj.version == 4 and ip_obj.is_private:
        return (0, host)
    if ip_obj.version == 6 and ip_obj.is_private:
        return (1, host)
    if ip_obj.version == 4:
        return (2, host)
    return (3, host)


def _discover_local_network_host() -> Optional[str]:
    candidates = set()

    for family, remote in (
        (socket.AF_INET, ("192.0.2.1", 80)),
        (socket.AF_INET6, ("2001:db8::1", 80, 0, 0)),
    ):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            sock.connect(remote)
            local_host = _normalize_ip_literal(sock.getsockname()[0])
            if local_host:
                candidates.add(local_host)
        except OSError:
            pass
        finally:
            sock.close()

    try:
        hostname = socket.gethostname()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            local_host = _normalize_ip_literal(sockaddr[0])
            if local_host:
                candidates.add(local_host)
    except socket.gaierror:
        pass

    filtered = []
    for host in candidates:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            continue
        filtered.append(host)

    if not filtered:
        return None
    return sorted(filtered, key=_rank_local_ip)[0]


def _format_url(host: str, port: int, path: str) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}{path}"


def _make_listener_socket(host: str, port: int) -> socket.socket:
    infos = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
        flags=socket.AI_PASSIVE,
    )
    if not infos:
        raise OSError(f"getaddrinfo() returned no results for {host}:{port}")
    last_error = None
    for family, socktype, proto, _canonname, sockaddr in infos:
        listener = None
        try:
            listener = socket.socket(family, socktype, proto)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
                with contextlib.suppress(OSError):
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(sockaddr)
            listener.listen(socket.SOMAXCONN)
            listener.settimeout(0.5)
            return listener
        except Exception as exc:
            last_error = exc
            if listener is not None:
                with contextlib.suppress(Exception):
                    listener.close()
    if last_error is not None:
        raise last_error
    raise OSError(f"Could not create listener for {host}:{port}")


def _http_date_now() -> str:
    return email.utils.formatdate(usegmt=True)


def _build_restart_placeholder_page(
    *,
    bind: str,
    port: int,
    path: str,
    restart_after_seconds: float,
) -> str:
    countdown = max(0.0, float(restart_after_seconds))
    countdown_display = f"{countdown:.1f}"
    location = html.escape(_format_url(_clickable_host(bind), port, path), quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="2">
  <title>ObstacleBridge restarting</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: \"Iosevka Aile\", \"IBM Plex Sans\", sans-serif;
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at top, rgba(255, 180, 120, 0.18), transparent 36%),
        linear-gradient(160deg, #172033 0%, #0b1220 100%);
      color: #f4f7fb;
    }}
    main {{
      width: min(34rem, calc(100vw - 2rem));
      padding: 1.5rem;
      border-radius: 18px;
      background: rgba(11, 18, 32, 0.82);
      border: 1px solid rgba(255, 255, 255, 0.12);
      box-shadow: 0 18px 60px rgba(0, 0, 0, 0.35);
    }}
    h1 {{
      margin: 0 0 0.75rem;
      font-size: 1.5rem;
    }}
    p {{
      margin: 0.5rem 0;
      line-height: 1.5;
    }}
    .countdown {{
      font-size: 2.5rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }}
    code {{
      font-family: \"Iosevka Term\", \"IBM Plex Mono\", monospace;
      word-break: break-all;
    }}
  </style>
</head>
<body>
  <main>
    <h1>ObstacleBridge is restarting</h1>
    <p>The runtime requested a delayed restart after a disconnect timeout.</p>
    <p class="countdown"><span id="countdown">{countdown_display}</span>s</p>
    <p>WebAdmin should return automatically at <code>{location}</code>.</p>
  </main>
  <script>
    (() => {{
      const deadline = Date.now() + {int(round(countdown * 1000.0))};
      const node = document.getElementById("countdown");
      const tick = () => {{
        const remaining = Math.max(0, (deadline - Date.now()) / 1000);
        node.textContent = remaining.toFixed(1);
      }};
      tick();
      setInterval(tick, 100);
    }})();
  </script>
</body>
</html>
"""


class _RestartCountdownServer:
    def __init__(self, notice: Dict[str, Any], restart_after_seconds: float) -> None:
        self.bind = str(notice["bind"])
        self.port = int(notice["port"])
        self.path = str(notice["path"])
        self._deadline_monotonic = time.monotonic() + max(0.0, float(restart_after_seconds))
        self._listener: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._listener = _make_listener_socket(self.bind, self.port)
        self._thread = threading.Thread(
            target=self._serve,
            name="ObstacleBridgeRestartCountdown",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            with contextlib.suppress(Exception):
                listener.close()
        if self._thread is not None:
            self._thread.join(timeout=1.5)
            self._thread = None

    def _seconds_remaining(self) -> float:
        return max(0.0, self._deadline_monotonic - time.monotonic())

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(1.0)
                self._handle_connection(conn)

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            request = conn.recv(4096)
        except OSError:
            return
        if not request:
            return
        first_line = request.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
        parts = first_line.split()
        method = parts[0].upper() if parts else ""
        request_path = parts[1] if len(parts) > 1 else self.path
        if method not in {"GET", "HEAD"}:
            self._send_response(
                conn,
                status="405 Method Not Allowed",
                content_type="text/plain; charset=utf-8",
                body=b"method not allowed\n",
            )
            return
        if request_path.startswith("/api/"):
            restart_in_seconds = self._seconds_remaining()
            payload = json.dumps(
                {
                    "ok": True,
                    "restart_pending": True,
                    "restart_in_seconds": round(restart_in_seconds, 3),
                    # Negative uptime is the remaining countdown while the
                    # supervised child is absent, for the normal WebAdmin UI.
                    "uptime_sec": -max(1, int(restart_in_seconds + 0.999)),
                    "admin_web_url": _format_url(_clickable_host(self.bind), self.port, self.path),
                }
            ).encode("utf-8")
            self._send_response(
                conn,
                status="200 OK",
                content_type="application/json; charset=utf-8",
                body=payload,
                head_only=(method == "HEAD"),
            )
            return
        body = _build_restart_placeholder_page(
            bind=self.bind,
            port=self.port,
            path=self.path,
            restart_after_seconds=self._seconds_remaining(),
        ).encode("utf-8")
        self._send_response(
            conn,
            status="200 OK",
            content_type="text/html; charset=utf-8",
            body=body,
            head_only=(method == "HEAD"),
        )

    def _send_response(
        self,
        conn: socket.socket,
        *,
        status: str,
        content_type: str,
        body: bytes,
        head_only: bool = False,
    ) -> None:
        headers = [
            f"HTTP/1.1 {status}",
            f"Date: {_http_date_now()}",
            "Connection: close",
            "Cache-Control: no-store, max-age=0",
            "Pragma: no-cache",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "",
            "",
        ]
        response = "\r\n".join(headers).encode("iso-8859-1")
        try:
            conn.sendall(response)
            if not head_only:
                conn.sendall(body)
        except OSError:
            return


def _discover_public_network_host() -> Tuple[Optional[str], Optional[str]]:
    for service_url in PUBLIC_IP_DISCOVERY_SERVICES:
        request = urllib.request.Request(
            service_url,
            headers={"User-Agent": "ObstacleBridge/0.1 public-ip-check"},
        )
        try:
            with urllib.request.urlopen(request, timeout=PUBLIC_IP_DISCOVERY_TIMEOUT_S) as response:
                payload = response.read().decode("utf-8", errors="replace").strip()
        except (OSError, urllib.error.URLError, TimeoutError):
            continue

        public_ip = _normalize_ip_literal(payload)
        if not public_ip:
            continue

        public_dns = None
        try:
            reverse_name, _, _ = socket.gethostbyaddr(public_ip)
        except (OSError, socket.herror, socket.gaierror):
            reverse_name = None
        if reverse_name and reverse_name != public_ip:
            public_dns = reverse_name.rstrip(".")
        return public_ip, public_dns

    return None, None


def _resolve_admin_web_notice_settings(forward_args: Sequence[str]) -> Optional[Dict[str, Any]]:
    parser = _build_bridge_notice_parser()
    argv = list(forward_args)
    explicit_config = any(arg in {"--config", "-c"} for arg in argv)
    bootstrap_args, _ = parser.parse_known_args(argv)

    if bootstrap_args.dump_config or bootstrap_args.save_config:
        return None

    config_defaults = _load_config_defaults(pathlib.Path(bootstrap_args.config), explicit_config)
    parser.set_defaults(
        admin_web=bool(config_defaults.get("admin_web", True)),
        admin_web_bind=str(config_defaults.get("admin_web_bind", "127.0.0.1") or "127.0.0.1"),
        admin_web_port=int(config_defaults.get("admin_web_port", 18080) or 18080),
        admin_web_path=str(config_defaults.get("admin_web_path", "/") or "/"),
    )
    effective_args, _ = parser.parse_known_args(argv)

    if not effective_args.admin_web:
        return None

    path = str(effective_args.admin_web_path or "/")
    if not path.startswith("/"):
        path = f"/{path}"

    return {
        "bind": str(effective_args.admin_web_bind or "127.0.0.1"),
        "port": int(effective_args.admin_web_port),
        "path": path,
    }

def _print_startup_notice_immediate(notice: Optional[Dict[str, Any]]) -> None:
    if not notice:
        return

    bind = str(notice["bind"])
    port = int(notice["port"])
    path = str(notice["path"])

    print(f"Open WebAdmin interface {_format_url(_clickable_host(bind), port, path)}", flush=True)


def _print_startup_notice_deferred(notice: Optional[Dict[str, Any]]) -> None:
    if not notice:
        return

    bind = str(notice["bind"])
    port = int(notice["port"])
    path = str(notice["path"])

    if not _is_wildcard_bind(bind):
        return

    lan_host = _discover_local_network_host()
    if lan_host and lan_host != "127.0.0.1":
        print(f"Open WebAdmin from local network {_format_url(lan_host, port, path)}", flush=True)

    print("Working on global IP address detection ...", flush=True)
    public_ip, public_dns = _discover_public_network_host()
    if public_ip:
        print(
            f"Public WebAdmin candidate {_format_url(public_ip, port, path)} (requires inbound routing/firewall access)",
            flush=True,
        )
    if public_ip and public_dns:
        print(
            f"Public DNS candidate {_format_url(public_dns, port, path)} (if that name resolves externally)",
            flush=True,
        )


def _run_process_once(
    cmd: Sequence[str],
    *,
    devnull: Optional[Any],
    post_start_hook: Optional[Any] = None,
) -> int:
    def _read_tail(handle: Any, limit: int = 4000) -> str:
        try:
            handle.flush()
            handle.seek(0, os.SEEK_END)
            size = int(handle.tell() or 0)
            handle.seek(max(0, size - limit))
            return handle.read().decode("utf-8", "replace").strip()
        except Exception:
            return ""

    def _maybe_report_hidden_failure(stderr_handle: Any, rc: int) -> None:
        if rc == 0:
            return
        stderr_tail = _read_tail(stderr_handle)
        if not stderr_tail:
            return
        print(
            "ObstacleBridge startup failed while launcher output redirection was active. "
            "Hidden child stderr follows:",
            file=sys.stderr,
            flush=True,
        )
        print(stderr_tail, file=sys.stderr, flush=True)

    if post_start_hook is None:
        if devnull is not None:
            with tempfile.TemporaryFile() as stdout_capture, tempfile.TemporaryFile() as stderr_capture:
                result = subprocess.run(cmd, stdout=stdout_capture, stderr=stderr_capture)
                rc = int(result.returncode)
                _maybe_report_hidden_failure(stderr_capture, rc)
                return rc
        else:
            result = subprocess.run(cmd)
        return int(result.returncode)

    popen_kwargs: Dict[str, Any] = {}
    if devnull is not None:
        with tempfile.TemporaryFile() as stdout_capture, tempfile.TemporaryFile() as stderr_capture:
            popen_kwargs["stdout"] = stdout_capture
            popen_kwargs["stderr"] = stderr_capture
            process = subprocess.Popen(cmd, **popen_kwargs)
            try:
                post_start_hook()
            except Exception:
                pass
            rc = int(process.wait())
            _maybe_report_hidden_failure(stderr_capture, rc)
            return rc

    process = subprocess.Popen(cmd, **popen_kwargs)
    try:
        post_start_hook()
    except Exception:
        pass
    return int(process.wait())


def _show_restart_countdown(notice: Optional[Dict[str, Any]], interval_seconds: float) -> None:
    if not notice or interval_seconds <= 0:
        time.sleep(interval_seconds)
        return
    placeholder = _RestartCountdownServer(notice, interval_seconds)
    try:
        placeholder.start()
    except OSError as exc:
        print(
            f"Restart holding page could not bind {notice['bind']}:{notice['port']}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(interval_seconds)
        return
    try:
        time.sleep(interval_seconds)
    finally:
        placeholder.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args, forward_args = parser.parse_known_args(argv)
    cmd = _resolve_command(args.command, forward_args)
    if args.command is None and not _maybe_offer_dependency_install(_missing_runtime_dependencies()):
        return 1
    startup_notice = _resolve_admin_web_notice_settings(forward_args) if args.command is None else None

    if args.command is None:
        _print_startup_notice_immediate(startup_notice)

    devnull = None
    if not args.no_redirect:
        devnull = open(os.devnull, "wb")

    try:
        while True:
            try:
                post_start_hook = None
                if startup_notice and _is_wildcard_bind(str(startup_notice["bind"])):
                    post_start_hook = lambda: _print_startup_notice_deferred(startup_notice)
                rc = _run_process_once(cmd, devnull=devnull, post_start_hook=post_start_hook)
            except FileNotFoundError as exc:
                print(f"Command not found: {exc}", file=sys.stderr)
                return 127
            if rc == 75:
                continue
            if rc == 77:
                _show_restart_countdown(startup_notice, args.interval)
                continue
            return rc
    finally:
        if devnull is not None:
            devnull.close()
