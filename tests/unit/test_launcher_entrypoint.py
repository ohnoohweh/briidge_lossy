from __future__ import annotations

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
