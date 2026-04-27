from __future__ import annotations

import json
import sys
from pathlib import Path

from .runner import (
    run_config_persistence_probe_sync,
    run_host_websocket_probe_sync,
    run_runtime_config_sync,
    run_ws_secure_link_probe_sync,
    run_ws_udp_echo_probe_sync,
    write_report,
)


def _arg_value(args: list[str], name: str, default: str | None = None) -> str:
    if name not in args:
        if default is not None:
            return default
        raise ValueError(f"{name} is required")
    index = args.index(name)
    try:
        return args[index + 1]
    except IndexError as exc:
        raise ValueError(f"{name} requires a value") from exc


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--config-persistence-probe" in args:
        try:
            timeout_sec = float(_arg_value(args, "--timeout-sec", "12"))
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "app": "obstacle_bridge_ios_e2e",
                        "probe": "config-persistence",
                        "error": f"invalid --config-persistence-probe arguments: {type(exc).__name__}: {exc}",
                    },
                    sort_keys=True,
                )
            )
            return 2

        report = run_config_persistence_probe_sync(timeout_sec=timeout_sec)
        report_path = write_report(report)
        print(json.dumps({**report, "report_path": str(report_path)}, indent=2, sort_keys=True))
        return 0 if bool(report.get("ok")) else 1

    if "--runtime-config" in args or "--runtime-config-json" in args:
        try:
            hold_sec = float(_arg_value(args, "--hold-sec", "600"))
            if "--runtime-config-json" in args:
                config = json.loads(_arg_value(args, "--runtime-config-json"))
            else:
                config_path = Path(_arg_value(args, "--runtime-config")).expanduser()
                config = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(config, dict):
                raise ValueError("runtime config root must be a JSON object")
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "app": "obstacle_bridge_ios_e2e",
                        "probe": "runtime-config",
                        "error": f"invalid --runtime-config arguments: {type(exc).__name__}: {exc}",
                    },
                    sort_keys=True,
                )
            )
            return 2

        report = run_runtime_config_sync(
            config=config,
            hold_sec=hold_sec,
        )
        report_path = write_report(report)
        print(json.dumps({**report, "report_path": str(report_path)}, indent=2, sort_keys=True))
        return 0 if bool(report.get("ok")) else 1

    if "--ws-secure-link-probe" in args:
        try:
            ws_url = _arg_value(args, "--ws-secure-link-probe")
            secure_link_psk = _arg_value(args, "--secure-link-psk")
            timeout_sec = float(_arg_value(args, "--timeout-sec", "12"))
            hold_after_success_sec = float(_arg_value(args, "--hold-after-success-sec", "3"))
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "app": "obstacle_bridge_ios_e2e",
                        "probe": "ws-secure-link",
                        "error": f"invalid --ws-secure-link-probe arguments: {type(exc).__name__}: {exc}",
                    },
                    sort_keys=True,
                )
            )
            return 2

        report = run_ws_secure_link_probe_sync(
            ws_url=ws_url,
            secure_link_psk=secure_link_psk,
            timeout_sec=timeout_sec,
            hold_after_success_sec=hold_after_success_sec,
        )
        report_path = write_report(report)
        print(json.dumps({**report, "report_path": str(report_path)}, indent=2, sort_keys=True))
        return 0 if bool(report.get("ok")) else 1

    if "--ws-udp-echo-probe" in args:
        try:
            ws_url = _arg_value(args, "--ws-udp-echo-probe")
            local_udp_port = int(_arg_value(args, "--local-udp-port"))
            target_udp_host = _arg_value(args, "--target-udp-host", "127.0.0.1")
            target_udp_port = int(_arg_value(args, "--target-udp-port"))
            payload = bytes.fromhex(_arg_value(args, "--payload-hex", "0130"))
            expected = bytes.fromhex(_arg_value(args, "--expected-hex", payload.hex()))
            timeout_sec = float(_arg_value(args, "--timeout-sec", "12"))
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "app": "obstacle_bridge_ios_e2e",
                        "probe": "ws-udp-echo",
                        "error": f"invalid --ws-udp-echo-probe arguments: {type(exc).__name__}: {exc}",
                    },
                    sort_keys=True,
                )
            )
            return 2

        report = run_ws_udp_echo_probe_sync(
            ws_url=ws_url,
            local_udp_port=local_udp_port,
            target_udp_host=target_udp_host,
            target_udp_port=target_udp_port,
            payload=payload,
            expected=expected,
            timeout_sec=timeout_sec,
        )
        report_path = write_report(report)
        print(json.dumps({**report, "report_path": str(report_path)}, indent=2, sort_keys=True))
        return 0 if bool(report.get("ok")) else 1

    if "--host-websocket-probe" not in args:
        print(
            json.dumps(
                {
                    "ok": False,
                    "app": "obstacle_bridge_ios_e2e",
                    "error": "missing --host-websocket-probe ws:// URL",
                },
                sort_keys=True,
            )
        )
        return 2

    arg_index = args.index("--host-websocket-probe")
    try:
        probe_url = args[arg_index + 1]
    except IndexError:
        print(
            json.dumps(
                {
                    "ok": False,
                    "app": "obstacle_bridge_ios_e2e",
                    "error": "--host-websocket-probe requires a ws:// URL",
                },
                sort_keys=True,
            )
        )
        return 2

    report = run_host_websocket_probe_sync(probe_url)
    report_path = write_report(report)
    print(json.dumps({**report, "report_path": str(report_path)}, indent=2, sort_keys=True))
    return 0 if bool(report.get("ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
