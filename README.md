# ObstacleBridge

This repository now uses a package-oriented Python layout for the ObstacleBridge project.

## Project layout

- `src/obstacle_bridge/` – application modules.
- `tests/unit/` – focused unit tests.
- `tests/integration/` – subprocess and end-to-end scenarios.
- `scripts/` – standalone development/test harness scripts.
- `docs/` – historical notes and testing documentation.

## Entry points

The renamed primary root-level entry point is:

- `ObstacleBridge.py`

Legacy wrappers are still available for compatibility:

- `udp_bidirectional_main.py`
- `udp_bidirectional_transfer.py`
- `overlay_tty.py`
- `extract_udp_debug.py`
- `run_udp_bidir_tests.py`

You can also invoke the packaged module with:

```bash
python -m obstacle_bridge --help
```
