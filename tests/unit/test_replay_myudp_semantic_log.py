from __future__ import annotations

from pathlib import Path

from obstacle_bridge.tools import replay_myudp_semantic_log


def test_replay_myudp_semantic_log_detects_regression_and_reset_match(tmp_path: Path) -> None:
    log_path = tmp_path / "udp.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-01-01 00:00:00,000 DEBUG udp_session: [RX] ctr=1 IN-ORDER -> advance expected=2",
                "2026-01-01 00:00:00,001 DEBUG udp_session: [RX] pending=[] missing=[] expected=2",
                "2026-01-01 00:00:00,002 DEBUG udp_session: [RX] pending=[5] missing=[2, 3, 4] expected=2",
                "2026-01-01 00:00:00,003 DEBUG udp_session: [RX] ctr=5 QUEUED (gap); frame_type=2 off/len=0 chunk_len=10",
                "2026-01-01 00:00:00,004 DEBUG udp_session: [RX] pending=[3000] missing=[1, 2, 3] expected=1",
                "2026-01-01 00:00:00,005 DEBUG udp_session: [RX] ctr=3000 QUEUED (gap); frame_type=2 off/len=0 chunk_len=10",
            ]
        ),
        encoding="utf-8",
    )

    report = replay_myudp_semantic_log.analyze_log(log_path)

    assert report["anomalies"]
    anomaly = report["anomalies"][0]
    assert anomaly["type"] == "expected_regressed"
    assert anomaly["from_expected"] == 2
    assert anomaly["to_expected"] == 1
    assert report["baseline"]["match_ratio"] < 1.0
    assert report["with_reset"]["compared_count"] == report["baseline"]["compared_count"]
