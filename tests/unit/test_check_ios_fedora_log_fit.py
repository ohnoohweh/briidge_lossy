from __future__ import annotations

from pathlib import Path

from obstacle_bridge.tools import check_ios_fedora_log_fit


def test_check_ios_fedora_log_fit_selects_shared_epoch(tmp_path: Path) -> None:
    ios_log = tmp_path / "vpn-obstaclebridge.log"
    fedora_log = tmp_path / "fedora.log"

    ios_log.write_text(
        "\n".join(
            [
                "2026-05-26 20:32:24,265 DEBUG udp_session: [UDP/PROTO] connection_made; local=('0.0.0.0', 63769) peername=None seeded_peer=None",
                "2026-05-26 20:32:24,570 DEBUG udp_session: [PEER/RX/RAW-SOCKET] len=19 from=('38.180.143.5', 4433) transport_sock=('0.0.0.0', 63769) transport_peer=None",
            ]
        ),
        encoding="utf-8",
    )
    fedora_log.write_text(
        "\n".join(
            [
                "2026-05-26 10:45:51,044 INFO udp_session: [UDP/SESSION] listener accepted peer_id=1 peer=('112.65.132.179', 60953)",
                "2026-05-26 12:32:24,509 INFO udp_session: [UDP/SESSION] listener accepted peer_id=1 peer=('112.65.132.179', 63769)",
                "2026-05-26 12:33:07,785 DEBUG udp_session: [PEER/RX] 111B <- ('0.0.0.0', 4433) <- ('112.65.132.179', 63769)",
            ]
        ),
        encoding="utf-8",
    )

    report = check_ios_fedora_log_fit.analyze_log_fit(ios_log, fedora_log)

    assert report["ok"] is True
    assert report["matching_ports"] == [63769]
    assert report["active_port"] == 63769
    assert any("Multiple Fedora peer epochs found" in warning for warning in report["warnings"])


def test_check_ios_fedora_log_fit_fails_without_shared_port(tmp_path: Path) -> None:
    ios_log = tmp_path / "vpn-obstaclebridge.log"
    fedora_log = tmp_path / "fedora.log"

    ios_log.write_text(
        "2026-05-26 20:32:24,265 DEBUG udp_session: [UDP/PROTO] connection_made; local=('0.0.0.0', 63769) peername=None seeded_peer=None\n",
        encoding="utf-8",
    )
    fedora_log.write_text(
        "2026-05-26 10:45:51,044 INFO udp_session: [UDP/SESSION] listener accepted peer_id=1 peer=('112.65.132.179', 60953)\n",
        encoding="utf-8",
    )

    report = check_ios_fedora_log_fit.analyze_log_fit(ios_log, fedora_log)

    assert report["ok"] is False
    assert report["matching_ports"] == []
    assert any("No shared UDP port" in warning for warning in report["warnings"])
