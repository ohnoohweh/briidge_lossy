from __future__ import annotations

import json
import urllib.error
from types import SimpleNamespace

from obstacle_bridge import launcher


def test_launcher_forwards_unknown_args_to_bridge(monkeypatch) -> None:
    calls = []

    def _fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(launcher.subprocess, "run", _fake_run)

    rc = launcher.main(["--no-redirect", "--udp-bind", "0.0.0.0", "--udp-own-port", "17000"])

    assert rc == 0
    assert len(calls) == 1
    cmd, kwargs = calls[0]
    assert kwargs == {}
    assert cmd[:4] == [launcher.sys.executable, "-m", "obstacle_bridge.bridge", "--config"]
    assert "ObstacleBridge.cfg" in cmd
    assert cmd[-4:] == ["--udp-bind", "0.0.0.0", "--udp-own-port", "17000"]


def test_launcher_restarts_for_code_75(monkeypatch) -> None:
    observed = []
    rcs = [75, 0]

    def _fake_run(cmd, **kwargs):
        observed.append(list(cmd))
        return SimpleNamespace(returncode=rcs.pop(0))

    monkeypatch.setattr(launcher.subprocess, "run", _fake_run)

    rc = launcher.main(["--no-redirect"])

    assert rc == 0
    assert len(observed) == 2


def test_launcher_waits_interval_for_code_77(monkeypatch) -> None:
    sleep_calls = []
    rcs = [77, 0]

    def _fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=rcs.pop(0))

    def _fake_sleep(sec):
        sleep_calls.append(sec)

    monkeypatch.setattr(launcher.subprocess, "run", _fake_run)
    monkeypatch.setattr(launcher.time, "sleep", _fake_sleep)

    rc = launcher.main(["--no-redirect", "--interval", "9"])

    assert rc == 0
    assert sleep_calls == [9]


def test_launcher_appends_unknown_args_to_custom_command(monkeypatch) -> None:
    calls = []

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(launcher.subprocess, "run", _fake_run)

    rc = launcher.main(["--no-redirect", "--command", "python -m obstacle_bridge.bridge", "--tcp-bind", "127.0.0.1"])

    assert rc == 0
    assert calls == [["python", "-m", "obstacle_bridge.bridge", "--tcp-bind", "127.0.0.1"]]


def test_launcher_prints_webadmin_url_from_default_config(monkeypatch, tmp_path, capsys) -> None:
    config_path = tmp_path / "ObstacleBridge.cfg"
    config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "0.0.0.0",
                    "admin_web_port": 18090,
                    "admin_web_path": "/",
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(launcher, "_discover_local_network_host", lambda: "192.168.1.77")
    monkeypatch.setattr(launcher, "_discover_public_network_host", lambda: (None, None))
    monkeypatch.setattr(
        launcher.subprocess,
        "run",
        lambda cmd, **kwargs: SimpleNamespace(returncode=0),
    )

    rc = launcher.main(["--no-redirect"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "Open WebAdmin interface http://127.0.0.1:18090/" in output
    assert "Open WebAdmin from local network http://192.168.1.77:18090/" in output


def test_launcher_prints_webadmin_url_with_cli_override(monkeypatch, tmp_path, capsys) -> None:
    config_path = tmp_path / "custom.cfg"
    config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "0.0.0.0",
                    "admin_web_port": 18090,
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(launcher, "_discover_local_network_host", lambda: "10.0.0.25")
    monkeypatch.setattr(launcher, "_discover_public_network_host", lambda: (None, None))
    monkeypatch.setattr(
        launcher.subprocess,
        "run",
        lambda cmd, **kwargs: SimpleNamespace(returncode=0),
    )

    rc = launcher.main(
        [
            "--no-redirect",
            "--config",
            str(config_path),
            "--admin-web-port",
            "18123",
            "--admin-web-path",
            "/status",
        ]
    )

    assert rc == 0
    output = capsys.readouterr().out
    assert "Open WebAdmin interface http://127.0.0.1:18123/status" in output
    assert "Open WebAdmin from local network http://10.0.0.25:18123/status" in output


def test_launcher_skips_webadmin_notice_when_disabled_in_config(monkeypatch, tmp_path, capsys) -> None:
    config_path = tmp_path / "ObstacleBridge.cfg"
    config_path.write_text(
        json.dumps({"admin_web": {"admin_web": False}}),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        launcher.subprocess,
        "run",
        lambda cmd, **kwargs: SimpleNamespace(returncode=0),
    )

    rc = launcher.main(["--no-redirect"])

    assert rc == 0
    assert capsys.readouterr().out == ""


def test_launcher_does_not_print_local_network_url_for_non_wildcard_bind(monkeypatch, tmp_path, capsys) -> None:
    config_path = tmp_path / "ObstacleBridge.cfg"
    config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "192.168.50.10",
                    "admin_web_port": 18090,
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(launcher, "_discover_local_network_host", lambda: "192.168.1.77")
    monkeypatch.setattr(launcher, "_discover_public_network_host", lambda: (None, None))
    monkeypatch.setattr(
        launcher.subprocess,
        "run",
        lambda cmd, **kwargs: SimpleNamespace(returncode=0),
    )

    rc = launcher.main(["--no-redirect"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "Open WebAdmin interface http://192.168.50.10:18090/" in output
    assert "Open WebAdmin from local network" not in output


def test_discover_local_network_host_prefers_private_ipv4(monkeypatch) -> None:
    class _FakeSocket:
        def __init__(self, family, socktype):
            self.family = family

        def connect(self, remote):
            return None

        def getsockname(self):
            if self.family == launcher.socket.AF_INET:
                return ("192.168.0.45", 54321)
            return ("fd00::45", 54321, 0, 0)

        def close(self):
            return None

    monkeypatch.setattr(launcher.socket, "socket", lambda family, socktype: _FakeSocket(family, socktype))
    monkeypatch.setattr(
        launcher.socket,
        "getaddrinfo",
        lambda host, port: [
            (launcher.socket.AF_INET, launcher.socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
            (launcher.socket.AF_INET6, launcher.socket.SOCK_STREAM, 0, "", ("fd00::99", 0, 0, 0)),
        ],
    )
    monkeypatch.setattr(launcher.socket, "gethostname", lambda: "test-host")

    assert launcher._discover_local_network_host() == "192.168.0.45"


def test_launcher_prints_public_candidates_for_wildcard_bind(monkeypatch, tmp_path, capsys) -> None:
    config_path = tmp_path / "ObstacleBridge.cfg"
    config_path.write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "0.0.0.0",
                    "admin_web_port": 18090,
                    "admin_web_path": "/",
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(launcher, "_discover_local_network_host", lambda: "192.168.1.77")
    monkeypatch.setattr(launcher, "_discover_public_network_host", lambda: ("203.0.113.9", "bridge.example.net"))
    monkeypatch.setattr(
        launcher.subprocess,
        "run",
        lambda cmd, **kwargs: SimpleNamespace(returncode=0),
    )

    rc = launcher.main(["--no-redirect"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "Public WebAdmin candidate http://203.0.113.9:18090/ (requires inbound routing/firewall access)" in output
    assert "Public DNS candidate http://bridge.example.net:18090/ (if that name resolves externally)" in output


def test_discover_public_network_host_uses_fallback_services(monkeypatch) -> None:
    attempted = []

    class _FakeResponse:
        def __init__(self, body: str):
            self._body = body

        def read(self):
            return self._body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def _fake_urlopen(request, timeout):
        attempted.append((request.full_url, timeout))
        if request.full_url == launcher.PUBLIC_IP_DISCOVERY_SERVICES[0]:
            raise urllib.error.URLError("blocked")
        return _FakeResponse("198.51.100.7\n")

    monkeypatch.setattr(launcher.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(launcher.socket, "gethostbyaddr", lambda host: ("public.example.net.", [], [host]))

    assert launcher._discover_public_network_host() == ("198.51.100.7", "public.example.net")
    assert attempted == [
        (launcher.PUBLIC_IP_DISCOVERY_SERVICES[0], launcher.PUBLIC_IP_DISCOVERY_TIMEOUT_S),
        (launcher.PUBLIC_IP_DISCOVERY_SERVICES[1], launcher.PUBLIC_IP_DISCOVERY_TIMEOUT_S),
    ]


def test_discover_public_network_host_returns_none_when_services_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        launcher.urllib.request,
        "urlopen",
        lambda request, timeout: (_ for _ in ()).throw(urllib.error.URLError("offline")),
    )

    assert launcher._discover_public_network_host() == (None, None)
