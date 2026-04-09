from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from obstacle_bridge.bridge import ConfigAwareCLI


def _register_sample_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sample", type=int, default=7)


def _make_cli() -> ConfigAwareCLI:
    return ConfigAwareCLI(description="unit-test-cli")


def test_parse_args_explicit_missing_config_uses_defaults(tmp_path: Path) -> None:
    cfg_path = tmp_path / "ObstacleBridge.cfg"
    cli = _make_cli()

    args = cli.parse_args(
        ["--config", str(cfg_path)],
        [("unit", _register_sample_option)],
    )

    assert args.sample == 7
    assert args._config_file_state == "missing"
    assert args._first_start_detected is True


def test_parse_args_empty_config_is_treated_as_first_start(tmp_path: Path) -> None:
    cfg_path = tmp_path / "ObstacleBridge.cfg"
    cfg_path.write_text("", encoding="utf-8")
    cli = _make_cli()

    args = cli.parse_args(
        ["--config", str(cfg_path)],
        [("unit", _register_sample_option)],
    )

    assert args.sample == 7
    assert args._config_file_state == "empty"
    assert args._first_start_detected is True


def test_parse_args_invalid_json_config_raises_clear_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "broken.json"
    cfg_path.write_text("{", encoding="utf-8")
    cli = _make_cli()

    with pytest.raises(ValueError, match="Invalid JSON config"):
        cli.parse_args(
            ["--config", str(cfg_path)],
            [("unit", _register_sample_option)],
        )
