from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import obstacle_bridge.bridge as bridge


def _git_result(*, returncode: int, stdout: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout)


def test_detect_build_info_prefers_live_git_over_generated_stamp(monkeypatch) -> None:
    monkeypatch.setattr(bridge, "_BUILD_INFO_CACHE", None)
    monkeypatch.setattr(
        bridge,
        "_load_generated_build_info",
        lambda: {"commit": "packaged", "source": "embedded-build-info", "tainted": True, "available": True},
    )
    responses = iter(
        [
            _git_result(returncode=0, stdout="livecommit\n"),
            _git_result(returncode=0, stdout=" M Package.resolved\n?? local-note\n"),
        ]
    )
    monkeypatch.setattr(bridge.subprocess, "run", lambda *args, **kwargs: next(responses))

    info = bridge._detect_build_info()

    assert info["commit"] == "livecommit"
    assert info["source"] == "git"
    assert info["tainted"] is True
    assert info["tracked_changes"] == 1
    assert info["untracked_changes"] == 1


def test_detect_build_info_uses_generated_stamp_without_git(monkeypatch) -> None:
    monkeypatch.setattr(bridge, "_BUILD_INFO_CACHE", None)
    generated = {"commit": "deployed", "source": "embedded-build-info", "tainted": False, "available": True}
    monkeypatch.setattr(bridge, "_load_generated_build_info", lambda: generated)
    monkeypatch.setattr(bridge.subprocess, "run", lambda *args, **kwargs: _git_result(returncode=128))

    assert bridge._detect_build_info() == {
        "commit": "deployed",
        "source": "embedded-build-info",
        "repo_root": "",
        "tainted": False,
        "tracked_changes": 0,
        "untracked_changes": 0,
        "available": True,
    }


def test_vps_updater_refreshes_build_metadata_before_syncing() -> None:
    updater = Path(__file__).resolve().parents[2] / "scripts" / "update_VPS.sh"
    content = updater.read_text(encoding="utf-8")

    assert '"${PYTHON_BIN}" "${SOURCE_DIR}/scripts/write_build_info.py"' in content
    assert content.index("write_build_info.py") < content.index('copy_path "src"')
